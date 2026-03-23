package authifygrpc

import (
	"context"
	"fmt"

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

	userData := map[string]any{
		"username": req.Username,
		"password": req.Password,
	}

	if err := s.auth.Store.CreateUser(userData); err != nil {
		return nil, err
	}

	return &Empty{}, nil
}

func (s *AuthifyGRPCServer) GenerateToken(ctx context.Context, req *GenerateTokenRequest) (*TokenResponse, error) {

	access, err := s.auth.Tokens.GenerateAccessToken(req.Username, req.Password)
	if err != nil {
		return nil, err
	}

	reqData := map[string]any{
		"ip": req.Device,
	}

	refresh, err := s.auth.Tokens.GenerateRefreshToken(req.Username, reqData)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
	}, nil
}

func (s *AuthifyGRPCServer) VerifyToken(ctx context.Context, req *VerifyTokenRequest) (*VerifyTokenResponse, error) {

	claims, err := s.auth.Tokens.VerifyAccessToken(req.AccessToken)
	if err != nil {
		return nil, err
	}

	return &VerifyTokenResponse{
		Claims: toStringMap(claims),
	}, nil
}

func (s *AuthifyGRPCServer) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*TokenResponse, error) {

	reqData := map[string]any{}

	access, _, err := s.auth.Tokens.RefreshToken(req.AccessToken, req.RefreshToken, reqData)
	if err != nil {
		return nil, err
	}

	return &TokenResponse{
		AccessToken: access,
	}, nil
}

func toStringMap(in map[string]any) map[string]string {
	out := make(map[string]string)

	for k, v := range in {
		out[k] = fmt.Sprintf("%v", v)
	}

	return out
}