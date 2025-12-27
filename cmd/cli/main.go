// Package main provides a CLI interface for interacting with the Authify
// authentication system. It allows creating users, generating tokens,
// verifying tokens, and refreshing tokens directly from the command line.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/HassanAli101/authify"
	"github.com/HassanAli101/authify/lib"
	"github.com/HassanAli101/authify/stores"
)

var (
	a   *authify.Authify
	cfg *lib.Config
)

func init() {
	var err error

	cfg, err = lib.ReadEnvVars()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}

	storeCfg, err := lib.LoadStoreConfig("configs/store.yml")
	if err != nil {
		log.Fatalf("Error loading store config: %v", err)
	}

	dbStore, err := stores.NewAuthifyDB(cfg.DatabaseURL, storeCfg.Table)
	if err != nil {
		log.Fatalf("Error connecting to db: %v", err)
	}

	jwtManager, err := authify.NewJWTManager().
		WithAccessSecret(cfg.JWTAccessSecret).
		WithRefreshSecret(cfg.JWTRefreshSecret).
		WithTokenDuration(cfg.TokenExpiration).
		WithStore(dbStore).
		Build()
	if err != nil {
		log.Fatalf("Error creating JWT manager: %v", err)
	}

	a = authify.NewAuthify(dbStore, jwtManager)
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {

	case "create-user":
		handleCreateUser()

	case "generate-token":
		handleGenerateToken()

	case "verify-token":
		handleVerifyToken()

	case "refresh-token":
		handleRefreshToken()

	default:
		fmt.Println("Unknown command:", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`
Authify CLI

Usage:
  authify <command> [options]

Commands:
  create-user     Create a new user
  generate-token  Generate access & refresh tokens
  verify-token    Verify an access token
  refresh-token   Refresh an access token

Run "authify <command> -h" for command-specific options.
`)
}

/* ===================== COMMAND HANDLERS ===================== */

func handleCreateUser() {
	cmd := flag.NewFlagSet("create-user", flag.ExitOnError)
	username := cmd.String("username", "", "Username")
	password := cmd.String("password", "", "Password")

	cmd.Parse(os.Args[2:])

	if *username == "" || *password == "" {
		log.Fatal("username and password are required")
	}

	err := a.Store.CreateUser(map[string]string{
		"username": *username,
		"password": *password,
	})
	if err != nil {
		log.Fatalf("Error creating user: %v", err)
	}

	fmt.Printf("User created: %s\n", *username)
}

func handleGenerateToken() {
	cmd := flag.NewFlagSet("generate-token", flag.ExitOnError)
	username := cmd.String("username", "", "Username")
	password := cmd.String("password", "", "Password")
	ip := cmd.String("ip", "cli", "Client identifier (IP or device)")

	cmd.Parse(os.Args[2:])

	if *username == "" || *password == "" {
		log.Fatal("username and password are required")
	}

	accessToken, err := a.Tokens.GenerateToken(*username, *password)
	if err != nil {
		log.Fatalf("Error generating access token: %v", err)
	}

	refreshToken, err := a.Tokens.GenerateRefreshToken(*username, *ip)
	if err != nil {
		log.Fatalf("Error generating refresh token: %v", err)
	}

	fmt.Println("Access Token:")
	fmt.Println(accessToken)
	fmt.Println("\nRefresh Token:")
	fmt.Println(refreshToken)
}

func handleVerifyToken() {
	cmd := flag.NewFlagSet("verify-token", flag.ExitOnError)
	token := cmd.String("token", "", "Access token")

	cmd.Parse(os.Args[2:])

	if *token == "" {
		log.Fatal("token is required")
	}

	username, role, err := a.Tokens.VerifyToken(*token, false)
	if err != nil {
		log.Fatalf("Token verification failed: %v", err)
	}

	fmt.Printf("Token valid\nUser: %s\nRole: %s\n", username, role)
}

func handleRefreshToken() {
	cmd := flag.NewFlagSet("refresh-token", flag.ExitOnError)
	accessToken := cmd.String("access", "", "Access token")
	refreshToken := cmd.String("refresh", "", "Refresh token")

	cmd.Parse(os.Args[2:])

	if *accessToken == "" || *refreshToken == "" {
		log.Fatal("both access and refresh tokens are required")
	}

	newToken, username, err := a.Tokens.RefreshToken(*accessToken, *refreshToken)
	if err != nil {
		log.Fatalf("Token refresh failed: %v", err)
	}

	fmt.Printf("Token refreshed for user: %s\nNew Access Token:\n%s\n", username, newToken)
}
