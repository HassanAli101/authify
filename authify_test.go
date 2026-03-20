package authify

import (
	"testing"
	"time"

	stores "github.com/HassanAli101/authify/stores"
	token "github.com/HassanAli101/authify/token"
)

var testStoreConfig = stores.StoreConfig{
	Name:       "users",
	AutoCreate: false,
	Columns: map[string]stores.ColumnConfig{
		"username": {
			Type:         "text",
			Required:     true,
			PrimaryKey:   true,
		},
		"password": {
			Type:       "text",
			Required:   true,
			Hidden:     true,
			IsPassword: true,
		},
		"role": {
			Type:     "text",
			Default:  "user",
			JWTClaim: "role",
		},
		"email": {
			Type:     "text",
			JWTClaim: "email",
		},
	},
}

var testTokenConfig = &token.TokenConfig{
	AccessToken: token.AccessTokenConfig{
		Duration:      time.Minute,
		SigningMethod: "HS256",
		Claims: map[string]token.ClaimConfig{
			"username": {
				Source:       "db",       // comes from user store
				Column:       "username",
				IsIdentifier: true,
			},
			"role": {
				Source: "db",
				Column: "role",
			},
			"email": {
				Source: "db",
				Column: "email",
			},
		},
	},
	RefreshToken: token.RefreshTokenConfig{
		Duration:         time.Hour * 24 * 3,
		AbsoluteDuration: time.Hour * 24 * 15,
		Claims: map[string]token.ClaimConfig{
			"username": {
				Source:       "db",
				Column:       "username",
				IsIdentifier: true,
			},
			"ip": {
				Source: "request",
				Header: "ip",
			},
			"user_agent": {
				Source: "request",
				Header: "user_agent",
			},
		},
	},
}


func setupAuthify() *Authify {
	memStore := stores.NewInMemoryUserStore(testStoreConfig)

	jwtManager, _ := token.NewJWTManager().
		WithAccessSecret("supersecret").
		WithRefreshSecret("supersecret2").
		WithStore(memStore).
		WithConfig(testTokenConfig).
		Build()

	a := NewAuthify(memStore, jwtManager)

	_ = a.Store.CreateUser(map[string]any{
		"username": "alice",
		"password": "password123",
		"role":     "user",
		"email":    "alice@example.com",
	})

	return a
}

// ----------------- User Creation Tests -----------------
func TestCreateUser(t *testing.T) {
	a := setupAuthify()

	err := a.Store.CreateUser(map[string]any{
		"username": "bob",
		"password": "securepass",
		"role":     "admin",
		"email":    "bob@example.com",
	})
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
}

// ----------------- Token Generation Tests -----------------
func TestGenerateAccessToken(t *testing.T) {
	a := setupAuthify()

	tokenStr, err := a.Tokens.GenerateAccessToken("alice", "password123")
	if err != nil {
		t.Fatalf("failed to generate access token: %v", err)
	}
	if tokenStr == "" {
		t.Fatalf("expected non-empty token string")
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	a := setupAuthify()

	reqData := map[string]any{"ip": "127.0.0.1"}
	refresh, err := a.Tokens.GenerateRefreshToken("alice", reqData)
	if err != nil {
		t.Fatalf("failed to generate refresh token: %v", err)
	}
	if refresh == "" {
		t.Fatalf("expected non-empty refresh token")
	}
}

// ----------------- Token Verification Tests -----------------
func TestVerifyAccessToken(t *testing.T) {
	a := setupAuthify()

	tokenStr, _ := a.Tokens.GenerateAccessToken("alice", "password123")
	claims, err := a.Tokens.VerifyAccessToken(tokenStr)
	if err != nil {
		t.Fatalf("failed to verify access token: %v", err)
	}

	expected := map[string]string{
		"username": "alice",
		"role":     "user",
		"email":    "alice@example.com",
	}

	for k, v := range expected {
		if claims[k] != v {
			t.Errorf("expected claim %s='%s', got '%v'", k, v, claims[k])
		}
	}
}

func TestTamperedToken(t *testing.T) {
	a := setupAuthify()

	tokenStr, _ := a.Tokens.GenerateAccessToken("alice", "password123")
	tampered := tokenStr + "tamper"

	_, err := a.Tokens.VerifyAccessToken(tampered)
	if err == nil {
		t.Errorf("expected error for tampered token, got nil")
	}
}

// ----------------- Token Refresh Tests -----------------
func TestRefreshAccessToken(t *testing.T) {
	a := setupAuthify()

	access, _ := a.Tokens.GenerateAccessToken("alice", "password123")
	refreshData := map[string]any{
		"ip":         "127.0.0.1",
		"user_agent": "unit-test",
	}
	refreshToken, _ := a.Tokens.GenerateRefreshToken("alice", refreshData)

	newAccess, _, err := a.Tokens.RefreshToken(access, refreshToken, refreshData)
	if err != nil {
		t.Fatalf("failed to refresh token: %v", err)
	}
	if newAccess == access {
		t.Errorf("expected refreshed token to differ from old token")
	}
}

// ----------------- Expired Token Tests -----------------
func TestExpiredAccessToken(t *testing.T) {
	memStore := stores.NewInMemoryUserStore(testStoreConfig)

	shortJWT, _ := token.NewJWTManager().
		WithAccessSecret("supersecret").
		WithRefreshSecret("supersecret2").
		WithStore(memStore).
		WithConfig(testTokenConfig).
		Build()

	a := NewAuthify(memStore, shortJWT)

	_ = a.Store.CreateUser(map[string]any{
		"username": "alice",
		"password": "password123",
	})

	tokenStr, _ := a.Tokens.GenerateAccessToken("alice", "password123")

	time.Sleep(time.Millisecond * 20)

	_, err := a.Tokens.VerifyAccessToken(tokenStr)
	if err == nil {
		t.Errorf("expected error verifying expired token, got nil")
	}
}

func TestAutoRefreshExpiredToken(t *testing.T) {
	memStore := stores.NewInMemoryUserStore(testStoreConfig)

	shortJWT, _ := token.NewJWTManager().
		WithAccessSecret("supersecret").
		WithRefreshSecret("supersecret2").
		WithStore(memStore).
		WithConfig(testTokenConfig).
		Build()

	a := NewAuthify(memStore, shortJWT)

	_ = a.Store.CreateUser(map[string]any{
		"username": "alice",
		"password": "password123",
	})

	access, _ := a.Tokens.GenerateAccessToken("alice", "password123")
	refreshData := map[string]any{
		"ip":         "127.0.0.1",
		"user_agent": "unit-test",
		"email":      "alice@example.com",
	}
	refreshToken, _ := a.Tokens.GenerateRefreshToken("alice", refreshData)

	time.Sleep(time.Second * 1)

	newAccess, _, err := a.Tokens.RefreshToken(access, refreshToken, refreshData)
	if err != nil {
		t.Fatalf("Failed to refresh expired token: %v", err)
	}

	claims, err := a.Tokens.VerifyAccessToken(newAccess)
	if err != nil {
		t.Fatalf("failed to verify refreshed token: %v", err)
	}
	if claims["username"] != "alice" || claims["role"] != "user" || claims["email"] != "alice@example.com" {
		t.Errorf("refreshed token missing expected claims: %v", claims)
	}
}