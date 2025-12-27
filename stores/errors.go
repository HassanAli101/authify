package stores

import (
	"errors"
)

var (
	// User-related errors
	ErrUserExists      = errors.New("user already exists")
	ErrUserNotFound    = errors.New("user not found")
	ErrInvalidPassword = errors.New("invalid password for user")
)
