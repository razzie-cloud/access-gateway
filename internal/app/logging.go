package app

import "github.com/google/uuid"

// User IDs are database UUIDs; never substitute a claimed username or cookie.
func userID(id []byte) string {
	value, err := uuid.FromBytes(id)
	if err != nil {
		return "unknown"
	}
	return value.String()
}
