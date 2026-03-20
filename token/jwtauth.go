package token

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// GenerateAccessToken validates user identifier/password using the database,
// fetches the associated role, and issues a signed JWT containing
// username, role, and an expiry timestamp.
// Returns a signed token string or an error if authentication fails.
func (m *JWTManager) GenerateAccessToken(userIdentifier, password string) (string, error) {
	// Fetch user info and validate password
	userData, err := m.store.GetUserInfo(userIdentifier, password)
	if err != nil {
		return "", err
	}

	// Build claims dynamically
	claims := m.buildClaims(m.cfg.AccessToken.Claims, userData, nil)

	// Always include issuer and expiry
	now := time.Now()
	claims[ClaimIssuer] = m.cfg.Issuer
	claims[ClaimExpiry] = now.Add(m.cfg.AccessToken.Duration).Unix()
	claims[ClaimIssued] = now.Unix()

	return m.signToken(claims, m.accessTokenSecretKey, m.cfg.AccessToken.SigningMethod)
}

// GenerateRefreshToken issues a refresh token with request metadata
func (m *JWTManager) GenerateRefreshToken(username string, requestData map[string]any) (string, error) {
	// Create a minimal user map to satisfy claims
	userData := map[string]any{
		"username": username,
	}

	claims := m.buildClaims(m.cfg.RefreshToken.Claims, userData, requestData)

	// Always include issuer and expiry
	now := time.Now()
	claims[ClaimIssuer] = m.cfg.Issuer
	claims[ClaimExpiry] = now.Add(m.cfg.RefreshToken.Duration).Unix()
	claims[ClaimIssued] = now.Unix()

	return m.signToken(claims, m.refreshTokenSecretKey, "HS256") // Refresh uses HS256
}


// VerifyAccessToken verifies an access token against the config.
// Returns claims map if valid, or error if invalid/expired.
func (m *JWTManager) VerifyAccessToken(tokenStr string) (jwt.MapClaims, error) {
	return m.verifyToken(tokenStr, m.accessTokenSecretKey, m.cfg.AccessToken.Claims, false)
}

// VerifyRefreshToken verifies a refresh token against the config.
// Returns claims map if valid, or error if invalid/expired.
func (m *JWTManager) VerifyRefreshToken(tokenStr string) (jwt.MapClaims, error) {
	return m.verifyToken(tokenStr, m.refreshTokenSecretKey, m.cfg.RefreshToken.Claims, true)
}

func (m *JWTManager) verifyToken(tokenStr string, secret string, claimConfig map[string]ClaimConfig, isRefresh bool) (jwt.MapClaims, error) {
	if tokenStr == "" {
		return nil, ErrInvalidToken
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrUnexpectedSigningMethod
		}
		return []byte(secret), nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, ErrClaimsInvalid
	}

	// Validate all configured claims
	for name, cfg := range claimConfig {
		val, exists := claims[name]
		if !exists && cfg.Source != "system" && cfg.Source != "static" {
			// Only system/static claims can be optional
			return nil, fmt.Errorf("missing claim: %s", name)
		}

		// Expiration check if configured as "exp"
		if cfg.Type == "exp" {
			if expFloat, ok := val.(float64); ok {
				if time.Now().After(time.Unix(int64(expFloat), 0)) {
					return nil, ErrTokenExpired
				}
			}
		}
	}

	return claims, nil
}

// RefreshToken issues a new access token based on a valid refresh token
// and optionally an expired access token (claims reuse)
func (m *JWTManager) RefreshToken(accessTokenStr, refreshTokenStr string, requestData map[string]any) (string, jwt.MapClaims, error) {
	// 1️⃣ Verify refresh token first
	refreshClaims, err := m.VerifyRefreshToken(refreshTokenStr)
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			return "", nil, ErrRefreshTokenExpired
		}
		return "", nil, err
	}

	// 2️⃣ Extract username from refresh token claims
	idClaim := m.identifierClaim()
	userIdentifier, ok := refreshClaims[idClaim].(string)
	if !ok || userIdentifier == "" {
		return "", nil, ErrMissingUserIdentifier
	}

	// 3️⃣ Optionally verify access token (ignore expiry)
	var accessClaims jwt.MapClaims
	if accessTokenStr != "" {
		accessClaims, _ = m.parseTokenWithoutExpiry(accessTokenStr, m.accessTokenSecretKey)
	}

	// 4️⃣ Build new claims for access token
	userData := map[string]any{
		idClaim: userIdentifier,
	}
	if accessClaims != nil {
		// Include old claims like role/email
		for k, v := range accessClaims {
			userData[k] = v
		}
	}

	newClaims := m.buildClaims(m.cfg.AccessToken.Claims, userData, requestData)
	now := time.Now()
	newClaims[ClaimIssuer] = m.cfg.Issuer
	newClaims[ClaimIssued] = now.Unix()
	newClaims[ClaimExpiry] = now.Add(m.cfg.AccessToken.Duration).Unix()

	token, err := m.signToken(newClaims, m.accessTokenSecretKey, m.cfg.AccessToken.SigningMethod)
	return token, newClaims, err
}

func (m *JWTManager) parseTokenWithoutExpiry(tokenStr string, secret string) (jwt.MapClaims, error) {
	parser := new(jwt.Parser)
	token, _, err := parser.ParseUnverified(tokenStr, jwt.MapClaims{})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrClaimsInvalid
	}
	return claims, nil
}

// buildClaims dynamically builds JWT claims based on config
func (m *JWTManager) buildClaims(cfg map[string]ClaimConfig, userData map[string]any, requestData map[string]any) jwt.MapClaims {
	claims := jwt.MapClaims{}

	for name, c := range cfg {
		switch c.Source {
		case "db":
			if val, ok := userData[c.Column]; ok {
				claims[name] = val
			}
		case "request":
			if val, ok := requestData[c.Header]; ok {
				claims[name] = val
			}
		case "system":
			switch c.Type {
			case "iat":
				claims[name] = time.Now().Unix()
			case "exp":
				continue
			case "timestamp":
				claims[name] = time.Now().UnixNano()
			}
		case "static":
			claims[name] = c.Value
		default:
			log.Printf("Unknown claim source for %s: %s", name, c.Source)
		}
	}

	return claims
}

func (m *JWTManager) signToken(claims jwt.MapClaims, secretKey string, method string) (string, error) {
	signMethod, ok := signingMethods[method]
	if !ok {
		return "", fmt.Errorf("unsupported signing method: %s", method)
	}

	token := jwt.NewWithClaims(signMethod, claims)
	return token.SignedString([]byte(secretKey))
}