// Package main starts the Authify authentication server.
// It sets up HTTP routes for creating users, generating tokens,
// verifying tokens, and refreshing tokens. The server reads
// its configuration (such as database URL, JWT secret, token
// expiration, server port, and table name) from environment
// variables. It initializes the database store, JWT manager,
// and Authify instance during startup and exposes endpoints
// for client interaction.
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/HassanAli101/authify"
	"github.com/HassanAli101/authify/lib"
)

var (
	a   *authify.Authify
	cfg *lib.Config
)

// init loads environment variables, establishes a database connection,
// initializes the JWT manager, and sets up the Authify instance.
// If any step fails, the application logs the error and exits.
func init() {
	var err error
	cfg, err = lib.ReadEnvVars()
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
		return
	}

	dbStore, err := authify.NewAuthifyDB(cfg.DatabaseURL, cfg.TableName)
	if err != nil {
		log.Fatalf("Error connecting to db %v\n", err)
		return
	}

	jwtManager, err := authify.NewJWTManager().
		WithAccessSecret(cfg.JWTAccessSecret).
		WithRefreshSecret(cfg.JWTRefreshSecret).
		WithTokenDuration(cfg.TokenExpiration).
		WithStore(dbStore).
		Build()
	if err != nil {
		log.Fatalf("Error creating a jwt manager instance %v\n", err)
	}
	a = authify.NewAuthify(dbStore, jwtManager)
}

// main is the entry point of the application.
// It registers HTTP handlers for authentication-related routes and
// starts the server on the configured port. If the server fails to
// start, it logs the error and terminates the program.
func main() {
	http.HandleFunc("/createUser", handleCreateUser)
	http.HandleFunc("/generateToken", handleGenerateToken)
	http.HandleFunc("/verifyToken", handleVerifyToken)
	http.HandleFunc("/refreshToken", handleRefreshToken)
	log.Printf("Server Listening at port %s\n", cfg.ServerPort)
	err := http.ListenAndServe(":"+cfg.ServerPort, nil)
	if err != nil {
		log.Fatalf("Error occured while listening: %v\n", err)
	}
}

// handleCreateUser handles the "/createUser" route.
// It reads the username and password from the request headers,
// creates a new user in the data store, and responds with a success
// message or an error. Logs the username when the user is created.
func handleCreateUser(w http.ResponseWriter, r *http.Request) {
	username, password, err := lib.ParseUsernamePassword(r)
	if err != nil {
		fmt.Fprint(w, fmt.Sprintf("Error occured while creating user: %v\n", err))
		return
	}
	err = a.Store.CreateUser(username, password)
	if err != nil {
		fmt.Fprintf(w, fmt.Sprintf("Error occured while creating user: %v\n", err))
		return
	}
	fmt.Fprint(w, "User created!\n")
	log.Printf("Created user with username: %v\n", username)
}

// handleGenerateToken handles the "/generateToken" route.
// It extracts the username and password from the request headers,
// generates a JWT token for the user if the credentials are valid,
// and responds with the token or an error. Logs the username when
// a token is successfully generated.
func handleGenerateToken(w http.ResponseWriter, r *http.Request) {
	ipAddress := r.RemoteAddr
	username, password, err := lib.ParseUsernamePassword(r)
	if err != nil {
		fmt.Fprint(w, fmt.Sprintf("Error occured while generating token: %v\n", err))
		return
	}
	accessToken, err := a.Tokens.GenerateToken(username, password)
	refreshToken, err := a.Tokens.GenerateRefreshToken(username, ipAddress)
	if err != nil {
		fmt.Fprintf(w, fmt.Sprintf("Error occured while generating token: %v\n", err))
		return
	}
	fmt.Fprint(w, fmt.Sprintf("Access Token: %v\nRefresh Token: %v\n", accessToken, refreshToken))
	log.Printf("Generated token for user with username: %v\n", username)
}

// handleVerifyToken handles the "/verifyToken" route.
// It extracts the token from the request headers, validates it,
// and responds with the associated username and role if the token
// is valid. Logs the username when the token is successfully verified.
func handleVerifyToken(w http.ResponseWriter, r *http.Request) {
	accessToken, _, err := lib.ParseToken(r)
	if err != nil {
		fmt.Fprint(w, fmt.Sprintf("Error occured while verifying token: %v\n", err))
		return
	}
	username, role, err := a.Tokens.VerifyToken(accessToken, false)
	if err != nil {
		fmt.Fprintf(w, fmt.Sprintf("Error occured while validating token: %v\n", err))
		return
	}
	fmt.Fprint(w, fmt.Sprintf("Token validated with user %v and their role: %v\n", username, role))
	log.Printf("Verified token for user with username: %v\n", username)
}

// handleRefreshToken handles the "/refreshToken" route.
// It extracts the token from the request headers, attempts to refresh it,
// and responds with the new token if successful. Logs the username when
// a token is refreshed.
func handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	accessToken, refreshToken, err := lib.ParseToken(r)
	if err != nil {
		fmt.Fprint(w, fmt.Sprintf("Error occured while refreshing token: %v\n", err))
		return
	}
	newToken, username, err := a.Tokens.RefreshToken(accessToken, refreshToken)
	if err != nil {
		fmt.Fprintf(w, fmt.Sprintf("Error occured while validating token: %v\n", err))
		return
	}
	fmt.Fprint(w, fmt.Sprintf("Token Refreshed! new token is: %v\n", newToken))
	log.Printf("Refreshed token for user with username: %v\n", username)
}
