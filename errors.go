package authify

import (
	"errors"

	"github.com/golang-jwt/jwt/v5"
)

var (
	// JWT-related errors
	ErrTokenExpired                  = jwt.ErrTokenExpired
	ErrUnexpectedSigningMethod       = errors.New("unexpected signing method")
	ErrInvalidToken                  = errors.New("token is invalid")
	ErrClaimsInvalid                 = errors.New("invalid claims")
	ErrMissingUsername               = errors.New("username missing in token")
	ErrMissingRole                   = errors.New("role missing in token")
	ErrRefreshTokenExpired           = errors.New("refresh token is expired, cannot do refresh, please log in again")
	ErrAccessTokenSecretNotProvided  = errors.New("access token secret not provided")
	ErrRefreshTokenSecretNotProvided = errors.New("refresh token secret not provided")

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

	// store errors
	ErrStoreNotProvided = errors.New("store must be provided")
)
