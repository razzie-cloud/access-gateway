package app

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAccountHeaderFollowsState(t *testing.T) {
	s := unitServer()
	for _, u := range []*User{nil, {Username: "<member>"}, {Username: "<admin>", IsAdmin: true}} {
		for _, name := range []string{"page", "state"} {
			w := httptest.NewRecorder()
			s.render(w, httptest.NewRequest("GET", "https://untrusted.example/ui/state", nil), 200, name, viewData{User: u})
			body := w.Body.String()
			if strings.Count(body, `id="account-header"`) != 1 {
				t.Fatal("header duplicated or absent", name)
			}
			if strings.Contains(body, `hx-swap-oob="innerHTML"`) != (name == "state") {
				t.Fatal("header swap must occur only for state responses", name)
			}
			if strings.Contains(body, `class="account-link"`) != (u != nil) {
				t.Fatal("identity not refreshed", name)
			}
			header := strings.Split(strings.Split(body, `id="account-header"`)[1], `</div>`)[0]
			if strings.Contains(header, ">Administrator<") != (u != nil && u.IsAdmin) {
				t.Fatal("incorrect header role", name)
			}
			if u != nil && !strings.Contains(header, `href="https://auth.example/"`) {
				t.Fatal("account link not bound to configured origin", name)
			}
			if strings.Contains(body, "<member>") || strings.Contains(body, "<admin>") {
				t.Fatal("unescaped username")
			}
			if strings.Contains(body, `account-strip`) {
				t.Fatal("duplicate identity strip")
			}
			if u != nil && strings.Count(body, `hx-post="/ui/logout"`) != 1 {
				t.Fatal("expected one logout form")
			}
		}
	}
}
