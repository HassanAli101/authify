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
	secretKey     string
	tokenDuration time.Duration
	store            Store
}

// This is for exporting and using the specific token expired message from the authify package.
var ErrTokenExpired = jwt.ErrTokenExpired

// NewJWTManager initializes a JWTManager with the given secret key, token expiry duration,
// and database reference for user validation.
func NewJWTManager(secretKey string, duration time.Duration, store Store) *JWTManager {
	return &JWTManager{
		secretKey:     secretKey,
		tokenDuration: duration,
		store:            store,
	}
}

// GenerateToken validates username/password using the database,
// fetches the associated role, and issues a signed JWT containing
// username, role, and an expiry timestamp.
// Returns a signed token string or an error if authentication fails.
// Documentation: https://pkg.go.dev/github.com/golang-jwt/jwt/v5
func (m *JWTManager) GenerateToken(username string, password string) (string, error) {
	role, err := m.store.GetUserRole(username, password)
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(m.tokenDuration).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(m.secretKey))
}

// VerifyToken parses and validates a JWT string. 
// Returns username, role, and an error if the token is invalid or expired.
// If the token is expired, it returns jwt.ErrTokenExpired specifically to allow seamless refresh handling.
func (m *JWTManager) VerifyToken(tokenStr string) (string, string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(m.secretKey), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", "",  jwt.ErrTokenExpired
		}
		return "", "", errors.New("invalid token")
	}

	if !token.Valid {
		return "", "", errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", "", errors.New("invalid claims")
	}

	username, ok := claims["username"].(string)
	if !ok {
		return "", "", errors.New("username missing in token")
	}
	role, ok := claims["role"].(string)
	if !ok {
		return "", "", errors.New("role missing in token")
	}

	if expVal, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(expVal), 0)
		if time.Now().After(expTime) {
			return "", "",  jwt.ErrTokenExpired
		}
	}

	return username, role, nil
}

// RefreshToken attempts to issue a new token using an existing one.
// If VerifyToken returns  jwt.ErrTokenExpired, the claims are reused to generate
// a fresh token with a new expiry. If the token is still valid, a new one 
// is issued regardless (ensuring clients always get a fresh token).
func (m *JWTManager) RefreshToken(tokenStr string) (string, error) {
	username, role, err := m.VerifyToken(tokenStr)
	if err != nil {
		fmt.Printf("error in verify token: %v\n", err)
		if errors.Is(err,  jwt.ErrTokenExpired) {
            token, _, err := new(jwt.Parser).ParseUnverified(tokenStr, jwt.MapClaims{})
            if err != nil {
                return "", err
            }
            claims := token.Claims.(jwt.MapClaims)
            username = claims["username"].(string)
            role, _ = claims["role"].(string)

            newClaims := jwt.MapClaims{
                "username": username,
                "role":     role,
                "exp":      time.Now().Add(m.tokenDuration).Unix(),
            }
            newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, newClaims)
            return newToken.SignedString([]byte(m.secretKey))
        }
		return "", err
	}

	claims := jwt.MapClaims{
		"username": username,
		"role":     role,
		"exp":      time.Now().Add(m.tokenDuration).Unix(),
		"refreshed_at": time.Now().UnixNano(),
	}

	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return newToken.SignedString([]byte(m.secretKey))
}
