package token

import (
	"time"
	"github.com/golang-jwt/jwt/v5"
)

const (
	defaultAccessTokenDuration = 15 * time.Minute
	authifyIssuer              = "authify-issuer"
	ClaimIssuer = "iss"
	ClaimExpiry = "exp"
	ClaimIssued = "iat"
)

var signingMethods = map[string]jwt.SigningMethod{
	"HS256": jwt.SigningMethodHS256,
	"HS512": jwt.SigningMethodHS512,
}

