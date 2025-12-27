package authify

import (
	"github.com/HassanAli101/authify/stores"
)

type Authify struct {
	Store  Store
	Tokens TokenManager
}

type Store interface {
	CreateUser(data map[string]string) error
	GetUserInfo(username, password string) (map[string]string, error)
	TableConfig() stores.TableConfig
}

type TokenManager interface {
	GenerateToken(username string, password string) (string, error)
	VerifyToken(tokenStr string, isRefresh bool) (string, string, error)
	RefreshToken(accessToken string, refreshToken string) (string, string, error)
	GenerateRefreshToken(username string, ipAddress string) (string, error)
}

func NewAuthify(store Store, tokens TokenManager) *Authify {
	return &Authify{
		Store:  store,
		Tokens: tokens,
	}
}
