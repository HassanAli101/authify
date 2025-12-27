package authify

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTManager is responsible for creating, verifying, and refreshing JWT tokens.
// It stores a secret key, token duration, and store interface.
type JWTManager struct {
	accessTokenSecretKey  string
	refreshTokenSecretKey string
	tokenDuration         time.Duration
	store                 Store
}

// NewJWTManager initializes a JWTManager with the given secret key, token expiry duration,
// and database store reference for user validation.
// all of these follow the builder pattern while making the jwt manager.
func NewJWTManager() *JWTManager {
	return &JWTManager{
		tokenDuration: defaultAccessTokenDuration,
	}
}

func (m *JWTManager) WithAccessSecret(secret string) *JWTManager {
	m.accessTokenSecretKey = secret
	return m
}

func (m *JWTManager) WithRefreshSecret(secret string) *JWTManager {
	m.refreshTokenSecretKey = secret
	return m
}

func (m *JWTManager) WithTokenDuration(d time.Duration) *JWTManager {
	m.tokenDuration = d
	return m
}

func (m *JWTManager) WithStore(store Store) *JWTManager {
	m.store = store
	return m
}

func (m *JWTManager) Build() (*JWTManager, error) {
	if m.accessTokenSecretKey == "" {
		return nil, ErrAccessTokenSecretNotProvided
	}
	if m.refreshTokenSecretKey == "" {
		return nil, ErrRefreshTokenSecretNotProvided
	}
	if m.store == nil {
		return nil, ErrStoreNotProvided
	}
	return m, nil
}

// GenerateToken validates username/password using the database,
// fetches the associated role, and issues a signed JWT containing
// username, role, and an expiry timestamp.
// Returns a signed token string or an error if authentication fails.
// Documentation: https://pkg.go.dev/github.com/golang-jwt/jwt/v5
func (m *JWTManager) GenerateToken(username string, password string) (string, error) {
	userInfo, err := m.store.GetUserInfo(username, password)
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"iss": authifyIssuer,
		"exp": time.Now().Add(m.tokenDuration).Unix(),
	}

	for k, v := range userInfo {
		claims[k] = v
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.accessTokenSecretKey))
}

// GenerateRefreshToken just generates a refresh token including user name, ipaddress
// issued at time, expire time, absolute expire time, and whether the token is valid or not
// uses the passed refreshTokenSecretKey
func (m *JWTManager) GenerateRefreshToken(username string, ipAddress string) (string, error) {
	claims := jwt.MapClaims{
		"uName":  username,
		"IpAddr": ipAddress,
		"iat":    time.Now().Unix(),
		"exp":    time.Now().AddDate(0, 0, 3).Unix(),
		"aExp":   time.Now().AddDate(0, 0, 15).Unix(),
		"valid":  "True",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.refreshTokenSecretKey))
}

// VerifyToken parses and validates a JWT string.
// Returns username, role, and an error if the token is invalid or expired.
// If the token is expired, it returns ErrTokenExpired specifically to allow seamless refresh handling.
func (m *JWTManager) VerifyToken(tokenStr string, isRefresh bool) (string, string, error) {
	secretKey := m.accessTokenSecretKey
	if isRefresh {
		secretKey = m.refreshTokenSecretKey
	}
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnexpectedSigningMethod
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			return "", "", ErrTokenExpired
		}
		return "", "", ErrInvalidToken
	}

	if !token.Valid {
		return "", "", ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", ErrClaimsInvalid
	}

	if expVal, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(expVal), 0)
		if time.Now().After(expTime) {
			return "", "", ErrTokenExpired
		}
	}

	if !isRefresh {
		username, ok := claims["username"].(string)
		if !ok {
			return "", "", ErrMissingUsername
		}
		role, ok := claims["role"].(string)
		if !ok {
			return "", "", ErrMissingRole
		}
		return username, role, nil
	}

	if isRefresh {
		valid, ok := claims["valid"].(string)
		if !ok || valid != "True" {
			return "", "", ErrInvalidToken
		}

		username, ok := claims["uName"].(string)
		if !ok {
			return "", "", ErrMissingUsername
		}
		return username, "", nil
	}
	return "", "", nil
}

// RefreshToken attempts to issue a new token using an existing one.
// If VerifyToken returns  ErrTokenExpired, the claims are reused to generate
// a fresh token with a new expiry. If the token is still valid, a new one
// is issued regardless (ensuring clients always get a fresh token).
func (m *JWTManager) RefreshToken(accessToken string, refreshToken string) (string, string, error) {
	username, _, err := m.VerifyToken(refreshToken, true)
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			return "", "", ErrRefreshTokenExpired
		}
		return "", "", err
	}
	username, role, err := m.VerifyToken(accessToken, false)
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			token, _, err := new(jwt.Parser).ParseUnverified(accessToken, jwt.MapClaims{})
			if err != nil {
				return "", "", err
			}
			claims := token.Claims.(jwt.MapClaims)
			username = claims["username"].(string)
			role, _ = claims["role"].(string)

			newClaims := jwt.MapClaims{
				"username":     username,
				"role":         role,
				"exp":          time.Now().Add(m.tokenDuration).Unix(),
				"refreshed_at": time.Now().UnixNano(),
			}
			newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
			newSignedToken, err := newToken.SignedString([]byte(m.accessTokenSecretKey))
			return newSignedToken, username, err
		}
		fmt.Printf("error in verify token: %v\n", err)
		return "", "", err
	}

	claims := jwt.MapClaims{
		"username":     username,
		"role":         role,
		"exp":          time.Now().Add(m.tokenDuration).Unix(),
		"refreshed_at": time.Now().UnixNano(),
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	newSignedToken, err := newToken.SignedString([]byte(m.accessTokenSecretKey))
	return newSignedToken, username, err
}
