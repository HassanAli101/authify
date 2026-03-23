package token

import (

	"github.com/HassanAli101/authify/stores"
	"github.com/golang-jwt/jwt/v5"
)

type TokenManager interface {
	GenerateAccessToken(userIdentifier, password string) (string, error)
	GenerateRefreshToken(username string, requestData map[string]any) (string, error)
	VerifyAccessToken(tokenStr string) (jwt.MapClaims, error)
	VerifyRefreshToken(tokenStr string) (jwt.MapClaims, error)
	RefreshToken(accessTokenStr, refreshTokenStr string, requestData map[string]any) (string, jwt.MapClaims, error) 
}

// JWTManager is responsible for creating, verifying, and refreshing JWT tokens.
// It stores a secret key, token duration, and store interface.
type JWTManager struct {
	cfg *TokenConfig
	accessTokenSecretKey  string
	refreshTokenSecretKey string
	store                 stores.Store
}

// NewJWTManager initializes a JWTManager with the given secret key, token expiry duration,
// and database store reference for user validation.
// all of these follow the builder pattern while making the jwt manager.
func NewJWTManager() *JWTManager {
	return &JWTManager{}
}

func (m *JWTManager) WithConfig(cfg *TokenConfig) *JWTManager {
	m.cfg = cfg
	return m
}

func (m *JWTManager) WithAccessSecret(secret string) *JWTManager {
	m.accessTokenSecretKey = secret
	return m
}

func (m *JWTManager) WithRefreshSecret(secret string) *JWTManager {
	m.refreshTokenSecretKey = secret
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

func (m *JWTManager) identifierClaim() string {
	for name, cfg := range m.cfg.AccessToken.Claims {
		if cfg.IsIdentifier {
			return name
		}
	}
	return ""
}
