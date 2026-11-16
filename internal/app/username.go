package app

import "strings"

const usernameValidationMessage = "username must contain 1–64 characters using only A–Z, a–z, 0–9, _, - and ."

func validUsername(username string) bool {
	if len(username) == 0 || len(username) > 64 {
		return false
	}
	for i := range len(username) {
		c := username[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// Valid usernames are ASCII, so this agrees with PostgreSQL lower(... COLLATE "C")
// and Lua string.lower. Keep the stored spelling for display and signed identity.
func canonicalUsername(username string) string {
	return strings.ToLower(username)
}
