package token

import (
	"time"

	"github.com/HassanAli101/authify/stores"
)

type TokenConfig struct {
}

type TokenManager interface {
	GenerateToken(username string, password string) (string, error)
	VerifyToken(tokenStr string, isRefresh bool) (string, string, error)
	RefreshToken(accessToken string, refreshToken string) (string, string, error)
	GenerateRefreshToken(username string, ipAddress string) (string, error)
}

// JWTManager is responsible for creating, verifying, and refreshing JWT tokens.
// It stores a secret key, token duration, and store interface.
type JWTManager struct {
	accessTokenSecretKey  string
	refreshTokenSecretKey string
	tokenDuration         time.Duration
	store                 stores.Store
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

func (m *JWTManager) WithStore(store stores.Store) *JWTManager {
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
		return nil, stores.ErrStoreNotProvided
	}
	return m, nil
}
