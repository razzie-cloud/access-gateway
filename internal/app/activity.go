package app

import (
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/razzie-cloud/access-gateway/internal/logging"
)

func (s *Server) activityActor(w http.ResponseWriter, r *http.Request, method string) (User, bool) {
	if r.Method != method {
		s.methodNotAllowed(w, r, method)
		return User{}, false
	}
	actor, err := s.currentUser(r)
	if err != nil {
		if errors.Is(err, errSessionStore) {
			logging.Fail(r.Context(), slog.LevelError, "redis", err)
			s.writeError(w, r, 503, "Session storage unavailable")
		} else {
			s.writeError(w, r, 401, "Sign in first")
		}
		return User{}, false
	}
	return actor, true
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	if actor, ok := s.activityActor(w, r, http.MethodGet); ok {
		s.renderActivity(w, r, actor, "")
	}
}

func (s *Server) activity(r *http.Request, actor User) (viewData, error) {
	data := viewData{User: &actor}
	if actor.IsAdmin {
		users, err := s.listUsers(r.Context())
		if err != nil {
			return data, err
		}
		for _, user := range users {
			id, err := uuid.FromBytes(user.ID)
			if err != nil {
				return data, err
			}
			data.AdminUsers = append(data.AdminUsers, adminUser{User: user, UUID: id.String()})
		}
	}
	devices, err := s.listDevices(r.Context(), actor)
	if err != nil {
		return data, err
	}
	sessions, err := s.sessions.ListSessions(r.Context())
	if err != nil {
		return data, err
	}
	cookie, _ := r.Cookie("auth") // activityActor has already authenticated it.
	currentID := hashToken(cookie.Value)
	for _, session := range sessions {
		if !actor.IsAdmin && session.Username != actor.Username {
			continue
		}
		view := sessionView{sessionSummary: session, DeviceName: "Unknown device", Current: session.ID == currentID || session.ParentID == currentID}
		for i := range devices {
			d := &devices[i]
			if d.Username != session.Username {
				continue
			}
			if session.DeviceID == d.ID {
				view.DeviceName = d.Name
				if view.Current {
					d.Current = true
				}
			}
			if session.DeviceID == d.ID || session.DeviceID == 0 {
				d.InUse = true
			}
		}
		data.Sessions = append(data.Sessions, view)
	}
	data.Devices = devices
	return data, nil
}

func (s *Server) renderActivity(w http.ResponseWriter, r *http.Request, actor User, message string) {
	data, err := s.activity(r, actor)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, errSessionStore) {
			status = http.StatusServiceUnavailable
		}
		logging.Fail(r.Context(), slog.LevelError, "load_activity", err)
		s.writeError(w, r, status, "Unable to load devices and sessions. Try refreshing the panel.")
		return
	}
	data.Message = message
	s.render(w, r, 200, "activity", data)
}

func (s *Server) handleRenameDevice(w http.ResponseWriter, r *http.Request) {
	s.handleDeviceChange(w, r, true)
}

func (s *Server) handleRemoveDevice(w http.ResponseWriter, r *http.Request) {
	s.handleDeviceChange(w, r, false)
}

func (s *Server) handleDeviceChange(w http.ResponseWriter, r *http.Request, rename bool) {
	actor, ok := s.activityActor(w, r, http.MethodPost)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, 400, "Invalid form")
		return
	}
	id, err := strconv.ParseInt(r.PostForm.Get("device_id"), 10, 64)
	if err != nil || id <= 0 {
		s.writeError(w, r, 400, "Invalid device")
		return
	}
	message := "Device removed."
	if rename {
		name := strings.TrimSpace(r.PostForm.Get("device_name"))
		if !validDeviceName(name) {
			s.writeError(w, r, 400, "Device name must contain 1–80 characters without control characters")
			return
		}
		err = s.renameDevice(r.Context(), actor, id, name)
		message = "Device renamed."
	} else {
		err = s.removeDevice(r.Context(), actor, id)
	}
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			s.writeError(w, r, 404, "Device not found")
		case errors.Is(err, errDeviceInUse):
			s.writeError(w, r, 409, "End this device’s sessions before removing it. Older sessions with an unknown device must also be ended.")
		case errors.Is(err, errSessionStore):
			logging.Fail(r.Context(), slog.LevelError, "redis", err)
			s.writeError(w, r, 503, "Session storage unavailable")
		default:
			logging.Fail(r.Context(), slog.LevelError, "application", err)
			s.writeError(w, r, 500, "Unable to update device")
		}
		return
	}
	if rename {
		logging.For(r.Context()).Debug("Device renamed", "event", "device.renamed", "actor_user_id", userID(actor.ID), "device_id", id)
	} else {
		logging.For(r.Context()).Info("Device removed", "event", "device.removed", "actor_user_id", userID(actor.ID), "device_id", id)
	}
	s.renderActivity(w, r, actor, message)
}

func (s *Server) handleRemoveSession(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.activityActor(w, r, http.MethodPost)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		s.writeError(w, r, 400, "Invalid form")
		return
	}
	id, kind := r.PostForm.Get("session_id"), r.PostForm.Get("kind")
	if !validSessionID(id) || (kind != "Gateway" && kind != "Application") {
		s.writeError(w, r, 400, "Invalid session")
		return
	}
	sessions, err := s.sessions.ListSessions(r.Context())
	if err != nil {
		logging.Fail(r.Context(), slog.LevelError, "redis", err)
		s.writeError(w, r, 503, "Session storage unavailable")
		return
	}
	cookie, _ := r.Cookie("auth")
	currentID := hashToken(cookie.Value)
	for _, session := range sessions {
		if session.ID != id || session.Kind != kind || (!actor.IsAdmin && session.Username != actor.Username) {
			continue
		}
		if session.ID == currentID || session.ParentID == currentID {
			s.writeError(w, r, 409, "This browser’s sessions are in use. Use Sign out to end them.")
			return
		}
		if err := s.sessions.DeleteSession(r.Context(), kind, id); err != nil {
			logging.Fail(r.Context(), slog.LevelError, "application", err)
			s.writeError(w, r, 503, "Unable to remove session")
			return
		}
		logging.For(r.Context()).Info("Session revoked", "event", "session.revoked", "actor_user_id", userID(actor.ID), "session_kind", kind)
		s.renderActivity(w, r, actor, "Session removed.")
		return
	}
	s.writeError(w, r, 404, "Session not found")
}
