package lib

import (
	"net/http"
	"os"
	"strconv"
	"time"
	"errors"

	"github.com/joho/godotenv"
)

type Config struct {
	DatabaseURL           string
	JWTSecret             string
	TokenExpiration       time.Duration
	ServerPort            string
	TableName             string
}

// ReadEnvVars loads configuration values from a .env file or system environment variables.
// It ensures required variables are present and valid, returning a Config struct with:
//   - DatabaseURL (connection string to the database)
//   - JWTSecret (secret key used for signing JWT tokens)
//   - TokenExpiration (duration in minutes for token validity)
//   - ServerPort (port for running the HTTP server)
//   - TableName (table name for storing users)
// If any required variable is missing or invalid, it returns an error.
// Documentation for godotenv: https://pkg.go.dev/github.com/joho/godotenv
func ReadEnvVars() (*Config, error) {
	if err := godotenv.Load(); err != nil {
    if os.Getenv("DATABASE_URL") == "" {
        return nil, errors.New("No .env file found and DATABASE_URL is missing")
    }
}

	cfg := &Config{}

	cfg.DatabaseURL = os.Getenv("DATABASE_URL")
	if cfg.DatabaseURL == "" {
		return nil, errors.New("DATABASE_URL is not set")
	}

	cfg.JWTSecret = os.Getenv("JWT_SECRET")
	if cfg.JWTSecret == "" {
		return nil, errors.New("JWT_SECRET is not set")
	}

	expStr := os.Getenv("TOKEN_EXPIRATION_TIME_MINUTES")
	if expStr == "" {
		return nil, errors.New("TOKEN_EXPIRATION_TIME_MINUTES is not set")
	}
	expMinutes, err := strconv.Atoi(expStr)
	if err != nil {
		return nil, errors.New("invalid TOKEN_EXPIRATION_TIME_MINUTES: " + err.Error())
	}
	cfg.TokenExpiration = time.Duration(expMinutes) * time.Minute

	cfg.ServerPort = os.Getenv("SERVER_PORT")
	if cfg.ServerPort == "" {
		return nil, errors.New("SERVER_PORT is not set")
	}

	cfg.TableName = os.Getenv("TABLE_NAME")
	if cfg.TableName == "" {
		return nil, errors.New("TABLE_NAME is not set")
	}

	return cfg, nil
}

// ParseUsernamePassword extracts the username and password from HTTP request headers.
// It expects the following headers:
//   - "authify-username": the username of the user
//   - "authify-password": the password of the user
// If either header is missing, it returns an error indicating which one is missing.
func ParseUsernamePassword(r *http.Request) (string, string, error) {
	username := r.Header.Get("authify-username")
	password := r.Header.Get("authify-password")
	if username == "" {
		return "", "", errors.New("username is missing in the request, please have a look at docs")
	}
	if password == "" {
		return "", "", errors.New("password is missing in the request, please have a look at docs")
	}
	return username, password, nil
}

// ParseToken extracts the JWT token from the HTTP request header.
// It expects the header:
//   - "authify-token": containing the JWT token string
// If the header is missing, it returns an error indicating the token is required.
func ParseToken(r *http.Request) (string, error) {
	token := r.Header.Get("authify-token")
	if token == "" {
		return "", errors.New("token is missing in the request, please have a look at docs")
	}
	return token, nil
}