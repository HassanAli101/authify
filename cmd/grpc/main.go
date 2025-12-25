// Package main starts the Authify gRPC server.
//
// This executable initializes configuration, database connectivity,
// JWT management, and the Authify core service, then exposes it over
// gRPC. The server listens on a TCP port and registers the Authify
// gRPC service implementation generated from protobuf definitions.
//
// This entrypoint is intended for internal or service-to-service
// communication (e.g., microservices), and complements the HTTP
// server provided in cmd/server.
package main

import (
	"log"
	"net"

	authify "github.com/HassanAli101/authify"
	authifygrpc "github.com/HassanAli101/authify/internal/grpc"
	"github.com/HassanAli101/authify/lib"
	"google.golang.org/grpc"
)

// main is the entry point for the Authify gRPC server.
//
// It performs the following steps:
//   1. Loads configuration values from environment variables.
//   2. Initializes the database-backed user store.
//   3. Builds a JWTManager using the configured secrets and token duration.
//   4. Constructs the Authify service with its dependencies.
//   5. Creates a TCP listener on port 50051.
//   6. Registers the Authify gRPC service implementation.
//   7. Starts serving incoming gRPC requests.
//
// If any critical step fails (such as binding the TCP port),
// the server logs the error and terminates.
func main() {
	// Load environment-based configuration.
	cfg, _ := lib.ReadEnvVars()

	// Initialize the user store backed by the configured database.
	store, _ := authify.NewAuthifyDB(cfg.DatabaseURL, cfg.TableName)

	// Build the JWT manager using the configured secrets and token lifetime.
	jwtManager, _ := authify.NewJWTManager().
		WithAccessSecret(cfg.JWTAccessSecret).
		WithRefreshSecret(cfg.JWTRefreshSecret).
		WithTokenDuration(cfg.TokenExpiration).
		WithStore(store).
		Build()

	// Initialize the core Authify service.
	auth := authify.NewAuthify(store, jwtManager)

	// Create a TCP listener for incoming gRPC connections.
	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatal(err)
	}

	// Create a new gRPC server instance.
	server := grpc.NewServer()

	// Register the Authify gRPC service implementation with the server.
	authifygrpc.RegisterAuthServiceServer(
		server,
		authifygrpc.NewAuthifyGRPCServer(auth),
	)

	log.Println("gRPC server listening on :50051")

	// Start serving incoming gRPC requests.
	if err := server.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
