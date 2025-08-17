package authify

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthifyDB struct {
    conn      *pgx.Conn
    ctx       context.Context
    tableName string
}

// This function takes in a connection string and a table name.
// It initializes a connection with the database, and sets its context as context.Background()
// After that, it attempts to create table if it does not exist with the passed tablename and required fields.
// The required fields are: unique "username", password and role.
// Documentation for pgx package: https://pkg.go.dev/github.com/jackc/pgx/v5
func NewAuthifyDB(connString string, tableName string) (*AuthifyDB, error) {
    ctx := context.Background()
    conn, err := pgx.Connect(ctx, connString)
    if err != nil {
        return nil, fmt.Errorf("unable to connect to database: %w", err)
    }

    db := &AuthifyDB{
        conn:      conn,
        ctx:       ctx,
        tableName: tableName,
    }

    if err = db.createTableIfNotExists(); err != nil {
        return nil, fmt.Errorf("Unable to Create Table: %w", err)
    }

    fmt.Println("Connection with database established")
    return db, nil
}


// This function takes in username and password 
// It creates the username with hashed password and default "user" role in database
// Noteworthy that the cost passed to GenerateFromPassword function is the default cost (10)
// Documentation for bcrypt: https://pkg.go.dev/golang.org/x/crypto/bcrypt
func (db *AuthifyDB) CreateUser(username string, password string) error {
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return fmt.Errorf("Error while encrypting the password: %v\n", err)
    }
   
    query := fmt.Sprintf(
        `INSERT INTO "%s" (username, password, role) VALUES ($1, $2, $3)`,
        db.tableName,
    )

    _, err = db.conn.Exec(db.ctx, query, username, string(hashedPassword), "user")
    if err != nil {
        return fmt.Errorf("unable to insert user: %w", err)
    }
    return nil
}

// This function takes in the username and password and returns role of user after validation
// uses bcrypt's CompareHashAndPassword function for password validation
func (db *AuthifyDB) GetUserRole(username string, password string) (string, error) {
    query := fmt.Sprintf(
        `SELECT password, role FROM "%s" WHERE username = $1`,
        db.tableName,
    )

    var hashedPassword, role string
    err := db.conn.QueryRow(db.ctx, query, username).Scan(&hashedPassword, &role)
    if err != nil {
        if err == pgx.ErrNoRows {
            return "", fmt.Errorf("no user found with username: %s", username)
        }
        return "", fmt.Errorf("unable to read user: %w", err)
    }

    err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
    if err != nil {
        return "", fmt.Errorf("invalid password for user: %s", username)
    }

    return role, nil
}

func (db *AuthifyDB) createTableIfNotExists() error {
    query := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS "%s" (
        username TEXT UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        PRIMARY KEY (username)
    );`, db.tableName)

    _, err := db.conn.Exec(db.ctx, query)

    if err != nil {
        return fmt.Errorf("Error while creating the table with tablename: %v\n", err)
    }
    return nil
}

