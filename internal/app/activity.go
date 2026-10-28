package app

import (
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

func (s *Server) activityActor(w http.ResponseWriter, r *http.Request, method string) (User, bool) {
	if r.Method != method {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return User{}, false
	}
	actor, err := s.currentUser(r)
	if err != nil {
		if errors.Is(err, errSessionStore) {
			render(w, 503, "message", viewData{Error: "Session storage unavailable"})
		} else {
			render(w, 401, "message", viewData{Error: "Sign in first"})
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
		render(w, status, "message", viewData{Error: "Unable to load devices and sessions. Try refreshing the panel."})
		return
	}
	data.Message = message
	render(w, 200, "activity", data)
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
		render(w, 400, "message", viewData{Error: "Invalid form"})
		return
	}
	id, err := strconv.ParseInt(r.PostForm.Get("device_id"), 10, 64)
	if err != nil || id <= 0 {
		render(w, 400, "message", viewData{Error: "Invalid device"})
		return
	}
	message := "Device removed."
	if rename {
		name := strings.TrimSpace(r.PostForm.Get("device_name"))
		if !validDeviceName(name) {
			render(w, 400, "message", viewData{Error: "Device name must contain 1–80 characters without control characters"})
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
			render(w, 404, "message", viewData{Error: "Device not found"})
		case errors.Is(err, errDeviceInUse):
			render(w, 409, "message", viewData{Error: "End this device’s sessions before removing it. Older sessions with an unknown device must also be ended."})
		case errors.Is(err, errSessionStore):
			render(w, 503, "message", viewData{Error: "Session storage unavailable"})
		default:
			render(w, 500, "message", viewData{Error: "Unable to update device"})
		}
		return
	}
	s.renderActivity(w, r, actor, message)
}

func (s *Server) handleRemoveSession(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.activityActor(w, r, http.MethodPost)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		render(w, 400, "message", viewData{Error: "Invalid form"})
		return
	}
	id, kind := r.PostForm.Get("session_id"), r.PostForm.Get("kind")
	if !validSessionID(id) || (kind != "Gateway" && kind != "Application") {
		render(w, 400, "message", viewData{Error: "Invalid session"})
		return
	}
	sessions, err := s.sessions.ListSessions(r.Context())
	if err != nil {
		render(w, 503, "message", viewData{Error: "Session storage unavailable"})
		return
	}
	cookie, _ := r.Cookie("auth")
	currentID := hashToken(cookie.Value)
	for _, session := range sessions {
		if session.ID != id || session.Kind != kind || (!actor.IsAdmin && session.Username != actor.Username) {
			continue
		}
		if session.ID == currentID || session.ParentID == currentID {
			render(w, 409, "message", viewData{Error: "This browser’s sessions are in use. Use Sign out to end them."})
			return
		}
		if err := s.sessions.DeleteSession(r.Context(), kind, id); err != nil {
			render(w, 503, "message", viewData{Error: "Unable to remove session"})
			return
		}
		s.renderActivity(w, r, actor, "Session removed.")
		return
	}
	render(w, 404, "message", viewData{Error: "Session not found"})
}
