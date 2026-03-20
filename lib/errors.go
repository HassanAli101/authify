package lib

import (
	"errors"
)

var (
	// User-related errors
	ErrUserExists      = errors.New("user already exists")
	ErrUserNotFound    = errors.New("user not found")
	ErrInvalidPassword = errors.New("invalid password for user")

	// Config / request errors
	ErrMissingDatabaseURL        = errors.New("DATABASE_URL is not set")
	ErrMissingJWTSecret          = errors.New("JWT_SECRET is not set")
	ErrMissingJWTRefreshSecret   = errors.New("JWT_REFRESH_SECRET is not set")
	ErrMissingTokenExpiration    = errors.New("TOKEN_EXPIRATION_TIME_MINUTES is not set")
	ErrInvalidTokenExpiration    = errors.New("invalid TOKEN_EXPIRATION_TIME_MINUTES")
	ErrMissingServerPort         = errors.New("SERVER_PORT is not set")
	ErrMissingTableName          = errors.New("TABLE_NAME is not set")
	ErrMissingUsernameHeader     = errors.New("username is missing in the request, please have a look at docs")
	ErrMissingPasswordHeader     = errors.New("password is missing in the request, please have a look at docs")
	ErrMissingAccessTokenHeader  = errors.New("access token is missing in the request, please have a look at docs")
	ErrMissingRefreshTokenHeader = errors.New("refresh token is missing in the request, please have a look at docs")
	ErrEnvNotFound               = errors.New("no .env file found and DATABASE_URL is missing")
)
