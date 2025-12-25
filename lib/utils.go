package lib

import (
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/HassanAli101/authify"
	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL      string
	JWTAccessSecret  string
	JWTRefreshSecret string
	TokenExpiration  time.Duration
	ServerPort       string
	TableName        string
}

// ReadEnvVars loads configuration values from a .env file or system environment variables.
func ReadEnvVars() (*Config, error) {
	if err := godotenv.Load(); err != nil {
		if os.Getenv("DATABASE_URL") == "" {
			return nil, authify.ErrEnvNotFound
		}
	}

	cfg := &Config{}

	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	if cfg.DatabaseURL == "" {
		return nil, authify.ErrMissingDatabaseURL
	}

	cfg.JWTAccessSecret = os.Getenv("JWT_SECRET")
	if cfg.JWTAccessSecret == "" {
		return nil, authify.ErrMissingJWTSecret
	}

	cfg.JWTRefreshSecret = os.Getenv("JWT_REFRESH_SECRET")
	if cfg.JWTRefreshSecret == "" {
		return nil, authify.ErrMissingJWTRefreshSecret
	}

	expStr := os.Getenv("TOKEN_EXPIRATION_TIME_MINUTES")
	if expStr == "" {
		return nil, authify.ErrMissingTokenExpiration
	}

	expMinutes, err := strconv.Atoi(expStr)
	if err != nil {
		return nil, authify.ErrInvalidTokenExpiration
	}
	cfg.TokenExpiration = time.Duration(expMinutes) * time.Minute

	cfg.ServerPort = os.Getenv("SERVER_PORT")
	if cfg.ServerPort == "" {
		return nil, authify.ErrMissingServerPort
	}

	cfg.TableName = os.Getenv("TABLE_NAME")
	if cfg.TableName == "" {
		return nil, authify.ErrMissingTableName
	}

	return cfg, nil
}

// ParseUsernamePassword extracts username and password from HTTP headers.
func ParseUsernamePassword(r *http.Request) (string, string, error) {
	username := r.Header.Get("authify-username")
	password := r.Header.Get("authify-password")

	if username == "" {
		return "", "", authify.ErrMissingUsernameHeader
	}
	if password == "" {
		return "", "", authify.ErrMissingPasswordHeader
	}

	return username, password, nil
}

// ParseToken extracts access and refresh tokens from HTTP headers.
func ParseToken(r *http.Request) (string, string, error) {
	accessToken := r.Header.Get("authify-access")
	refreshToken := r.Header.Get("authify-refresh")

	if accessToken == "" {
		return "", "", authify.ErrMissingAccessTokenHeader
	}
	if refreshToken == "" {
		return "", "", authify.ErrMissingRefreshTokenHeader
	}

	return accessToken, refreshToken, nil
}
