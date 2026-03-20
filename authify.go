package authify

import (
	"github.com/HassanAli101/authify/stores"
	"github.com/HassanAli101/authify/token"
)

type Authify struct {
	Store  stores.Store
	Tokens token.TokenManager
}

func NewAuthify(store stores.Store, tokens token.TokenManager) *Authify {
	return &Authify{
		Store:  store,
		Tokens: tokens,
	}
}
