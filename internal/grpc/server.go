package authifygrpc

import (
	"context"

	"github.com/HassanAli101/authify"
)

type AuthifyGRPCServer struct {
	UnimplementedAuthServiceServer
	auth *authify.Authify
}

func NewAuthifyGRPCServer(a *authify.Authify) *AuthifyGRPCServer {
	return &AuthifyGRPCServer{auth: a}
}

func (s *AuthifyGRPCServer) CreateUser(ctx context.Context, req *CreateUserRequest) (*Empty, error) {
	err := s.auth.Store.CreateUser(map[string]string{
	"username": req.Username,
	"password": req.Password,
})
	if err != nil {
		return nil, err
	}
	return &Empty{}, nil
}

func (s *AuthifyGRPCServer) GenerateToken(ctx context.Context, req *GenerateTokenRequest) (*TokenResponse, error) {
	access, err := s.auth.Tokens.GenerateToken(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	refresh, err := s.auth.Tokens.GenerateRefreshToken(req.Username, req.Device)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

func (s *AuthifyGRPCServer) VerifyToken(ctx context.Context, req *VerifyTokenRequest) (*VerifyTokenResponse, error) {
	username, role, err := s.auth.Tokens.VerifyToken(req.AccessToken, false)
	if err != nil {
		return nil, err
	}

	return &VerifyTokenResponse{
		Username: username,
		Role:     role,
	}, nil
}

func (s *AuthifyGRPCServer) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*TokenResponse, error) {
	access, _, err := s.auth.Tokens.RefreshToken(req.AccessToken, req.RefreshToken)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: access,
	}, nil
}
