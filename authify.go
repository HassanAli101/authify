package authify

type Authify struct {
    Store Store
    Tokens TokenManager
}

type Store interface {
    CreateUser(username, password string) error
    GetUserRole(username string, password string) (role string, err error)
}

type TokenManager interface {
    GenerateToken(username string, password string) (string, error)
    VerifyToken(tokenStr string, isRefresh bool) (string, string, error)
    RefreshToken(accessToken string, refreshToken string) (string, string, error)
    GenerateRefreshToken(username string, ipAddress string) (string, error) 
}

func NewAuthify(store Store, tokens TokenManager) *Authify {
    return &Authify{
        Store: store,
        Tokens: tokens,
    }
}
