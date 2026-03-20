package token

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
)
