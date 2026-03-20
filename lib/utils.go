package lib

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HassanAli101/authify/stores"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v2"
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
			return nil, ErrEnvNotFound
		}
	}

	cfg := &Config{}

	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	if cfg.DatabaseURL == "" {
		return nil, ErrMissingDatabaseURL
	}

	cfg.JWTAccessSecret = os.Getenv("JWT_SECRET")
	if cfg.JWTAccessSecret == "" {
		return nil, ErrMissingJWTSecret
	}

	cfg.JWTRefreshSecret = os.Getenv("JWT_REFRESH_SECRET")
	if cfg.JWTRefreshSecret == "" {
		return nil, ErrMissingJWTRefreshSecret
	}

	expStr := os.Getenv("TOKEN_EXPIRATION_TIME_MINUTES")
	if expStr == "" {
		return nil, ErrMissingTokenExpiration
	}

	expMinutes, err := strconv.Atoi(expStr)
	if err != nil {
		return nil, ErrInvalidTokenExpiration
	}
	cfg.TokenExpiration = time.Duration(expMinutes) * time.Minute

	cfg.ServerPort = os.Getenv("SERVER_PORT")
	if cfg.ServerPort == "" {
		return nil, ErrMissingServerPort
	}

	cfg.TableName = os.Getenv("TABLE_NAME")
	if cfg.TableName == "" {
		return nil, ErrMissingTableName
	}

	return cfg, nil
}

// ParseUsernamePassword extracts username and password from HTTP headers.
func ParseUserHeaders(r *http.Request, storeCfg stores.StoreConfig) (map[string]any, error) {
	userData := make(map[string]any)

	for name, cfg := range storeCfg.Columns {
		headerName := fmt.Sprintf("authify-%s", strings.ToLower(name))
		val := r.Header.Get(headerName)

		if cfg.Required && val == "" {
			return nil, fmt.Errorf("missing required header: %s", headerName)
		}

		if val != "" {
			userData[name] = val
		}
	}

	return userData, nil
}

// ParseToken extracts access and refresh tokens from HTTP headers.
func ParseToken(r *http.Request) (string, string, error) {
	accessToken := r.Header.Get("authify-access")
	refreshToken := r.Header.Get("authify-refresh")

	if accessToken == "" {
		return "", "", ErrMissingAccessTokenHeader
	}
	if refreshToken == "" {
		return "", "", ErrMissingRefreshTokenHeader
	}

	return accessToken, refreshToken, nil
}

func LoadStoreConfig(path string) (*stores.StoreConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg stores.StoreConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	out, err := yaml.Marshal(&cfg)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal config for printing: %w", err)
	}

	log.Printf("Loaded Store Config:\n%s\n", string(out))

	return &cfg, nil
}

// func LoadTokenConfig(path string) ()
