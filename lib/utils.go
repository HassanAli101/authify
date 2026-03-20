package lib

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/HassanAli101/authify/stores"
	"github.com/HassanAli101/authify/token"
	"github.com/joho/godotenv"
	"gopkg.in/yaml.v2"
)

type Config struct {
	DatabaseURL      string
	JWTAccessSecret  string
	JWTRefreshSecret string
	ServerPort       string
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

	cfg.ServerPort = os.Getenv("SERVER_PORT")
	if cfg.ServerPort == "" {
		return nil, ErrMissingServerPort
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
func ParseAccessToken(r *http.Request) (string, error) {
	accessToken := r.Header.Get("authify-access")

	if accessToken == "" {
		return "", ErrMissingAccessTokenHeader
	}

	return accessToken, nil
}

func ParseRefreshToken(r *http.Request) (string, error) {
	refreshToken := r.Header.Get("authify-refresh")

	if refreshToken == "" {
		return "", ErrMissingRefreshTokenHeader
	}

	return refreshToken, nil
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

func LoadTokenConfig(path string) (*token.TokenConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg token.TokenConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}