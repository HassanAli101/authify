package authify

import (
	"testing"
	"time"
)

func setupAuthify() *Authify {
	memStore := NewInMemoryUserStore()
	jwtManager := NewJWTManager("supersecret", "supersecret2", time.Minute*1, memStore)
	a := NewAuthify(memStore, jwtManager)

	_ = a.Store.CreateUser("alice", "password123")
	return a
}

func TestCreateUser(t *testing.T) {
	a := setupAuthify()

	err := a.Store.CreateUser("bob", "securepass")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}
}

func TestGenerateToken(t *testing.T) {
	a := setupAuthify()

	tokenStr, err := a.Tokens.GenerateToken("alice", "password123")
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}
	if tokenStr == "" {
		t.Fatalf("expected non-empty token string")
	}
}

func TestVerifyToken(t *testing.T) {
	a := setupAuthify()

	tokenStr, _ := a.Tokens.GenerateToken("alice", "password123")
	username, role, err := a.Tokens.VerifyToken(tokenStr, false)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}
	if username != "alice" {
		t.Errorf("expected username 'alice', got '%s'", username)
	}
	if role != "user" {
		t.Errorf("expected role 'user', got '%s'", role)
	}
}

func TestTamperedToken(t *testing.T) {
	a := setupAuthify()

	tokenStr, _ := a.Tokens.GenerateToken("alice", "password123")
	tampered := tokenStr + "extra"

	_, _, err := a.Tokens.VerifyToken(tampered, false)
	if err == nil {
		t.Errorf("expected error for tampered token, got nil")
	}
}

func TestRefreshToken(t *testing.T) {
	a := setupAuthify()

	tokenStr, _ := a.Tokens.GenerateToken("alice", "password123")
	refreshToken, _ := a.Tokens.GenerateRefreshToken("alice", "12345")
	newToken, _, err := a.Tokens.RefreshToken(tokenStr, refreshToken)
	if err != nil {
		t.Fatalf("failed to refresh token: %v", err)
	}
	if newToken == tokenStr {
		t.Errorf("expected refreshed token to differ from old token")
	}
}

func TestExpiredToken(t *testing.T) {
	memStore := NewInMemoryUserStore()
	shortLivedJWT := NewJWTManager("supersecret", "supersecret2", time.Millisecond*10, memStore)
	a := NewAuthify(memStore, shortLivedJWT)
	_ = a.Store.CreateUser("alice", "password123")

	tokenStr, err := a.Tokens.GenerateToken("alice", "password123")
	if err != nil {
		t.Fatalf("failed to generate short-lived token: %v", err)
	}

	time.Sleep(time.Millisecond * 20)

	_, _, err = a.Tokens.VerifyToken(tokenStr, false)
	if err == nil {
		t.Errorf("expected error verifying expired token, got nil")
	}
}

func TestAutoRefreshExpiredToken(t *testing.T) {
	memStore := NewInMemoryUserStore()
	shortLivedJWT := NewJWTManager("supersecret", "supersecret2", time.Second*1, memStore)
	a := NewAuthify(memStore, shortLivedJWT)
	_ = a.Store.CreateUser("alice", "password123")

	tokenStr, err := a.Tokens.GenerateToken("alice", "password123")
	if err != nil {
		t.Fatalf("failed to generate short-lived token: %v", err)
	}
	refreshToken, _ := a.Tokens.GenerateRefreshToken("alice", "12345")

	time.Sleep(time.Second * 1)

	tokenStr, _, err = a.Tokens.RefreshToken(tokenStr, refreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh expired token: %v\n", err)
	}

	username, role, err := a.Tokens.VerifyToken(tokenStr, false)
	if err != nil {
		t.Fatalf("failed to verify token: %v", err)
	}
	if username != "alice" {
		t.Errorf("expected username 'alice', got '%s'", username)
	}
	if role != "user" {
		t.Errorf("expected role 'user', got '%s'", role)
	}

}
