package stores

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthifyDB struct {
	conn     *pgx.Conn
	ctx      context.Context
	tableCfg TableConfig
}

// This function takes in a connection string and a table name.
// It initializes a connection with the database, and sets its context as context.Background()
// After that, it attempts to create table if it does not exist with the passed tablename and config in the store.yml file.
// Documentation for pgx package: https://pkg.go.dev/github.com/jackc/pgx/v5
func NewAuthifyDB(connString string, cfg TableConfig) (*AuthifyDB, error) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	db := &AuthifyDB{
		conn:     conn,
		ctx:      ctx,
		tableCfg: cfg,
	}

	if cfg.AutoCreate {
		if err = db.createTableIfNotExists(); err != nil {
			return nil, fmt.Errorf("Unable to Create Table: %w", err)
		}
	}

	log.Println("Connection with database established")
	return db, nil
}

// This function takes in username and password
// It creates the username with hashed password and provided information, as per config in database
// Noteworthy that the cost passed to GenerateFromPassword function is the default cost (10)
// Documentation for bcrypt: https://pkg.go.dev/golang.org/x/crypto/bcrypt
func (db *AuthifyDB) CreateUser(data map[string]string) error {
	cols := []string{}
	args := []any{}
	placeholders := []string{}

	i := 1
	for name, cfg := range db.tableCfg.Columns {
		val, ok := data[name]

		if cfg.Required && !ok && cfg.Default == "" {
			return fmt.Errorf("missing required field: %s", name)
		}

		if !ok {
			continue
		}

		if name == "password" {
			hash, err := bcrypt.GenerateFromPassword([]byte(val), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			val = string(hash)
		}

		cols = append(cols, fmt.Sprintf(`"%s"`, name))
		args = append(args, val)
		placeholders = append(placeholders, fmt.Sprintf("$%d", i))
		i++
	}

	query := fmt.Sprintf(
		`INSERT INTO "%s" (%s) VALUES (%s)`,
		db.tableCfg.Name,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
	)

	_, err := db.conn.Exec(db.ctx, query, args...)
	return err
}

// This function takes in the username and password and returns info of user after validation
// uses bcrypt's CompareHashAndPassword function for password validation
func (db *AuthifyDB) GetUserInfo(username, password string) (map[string]string, error) {
	var selectCols []string

	for name, _ := range db.tableCfg.Columns {
		// if cfg.Hidden {
		// 	continue
		// }
		selectCols = append(selectCols, fmt.Sprintf(`"%s"`, name))
	}

	query := fmt.Sprintf(
		`SELECT %s FROM "%s" WHERE username = $1`,
		strings.Join(selectCols, ", "),
		db.tableCfg.Name,
	)

	row := db.conn.QueryRow(db.ctx, query, username)

	values := make([]any, len(selectCols))
	valuePtrs := make([]any, len(selectCols))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	if err := row.Scan(valuePtrs...); err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	// Validate password
	pwIdx := -1
	for i, col := range selectCols {
		if col == `"password"` {
			pwIdx = i
			break
		}
	}

	if pwIdx == -1 {
		return nil, fmt.Errorf("password column not configured")
	}

	if err := bcrypt.CompareHashAndPassword(
		[]byte(values[pwIdx].(string)),
		[]byte(password),
	); err != nil {
		return nil, ErrInvalidPassword
	}

	// Build result map
	result := map[string]string{}
	i := 0
	for name, _ := range db.tableCfg.Columns {
		// if cfg.Hidden {
		// 	continue
		// }
		result[name] = fmt.Sprintf("%v", values[i])
		i++
	}

	return result, nil
}

func (db *AuthifyDB) TableConfig() TableConfig {
	return db.tableCfg
}

func (db *AuthifyDB) createTableIfNotExists() error {
	if !db.tableCfg.AutoCreate {
		return nil
	}

	cols, primaryKeys, err := db.constructColumnRowFromConfig(db.tableCfg.Columns)
	if err != nil {
		return err
	}

	if len(primaryKeys) > 0 {
		cols = append(cols, fmt.Sprintf("PRIMARY KEY (%s)",
			strings.Join(primaryKeys, ", ")))
	}

	query := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS "%s" (%s);`,
		db.tableCfg.Name,
		strings.Join(cols, ", "),
	)

	_, err = db.conn.Exec(db.ctx, query)
	return err
}

func (db *AuthifyDB) constructColumnRowFromConfig(columns map[string]ColumnConfig) (cols []string, primaryKeys []string, err error) {
	for name, cfg := range db.tableCfg.Columns {
		sqlType, ok := allowedTypes[cfg.Type]
		if !ok {
			err = errors.New(fmt.Sprintf("unsupported column type: %s", cfg.Type))
			return
		}

		col := fmt.Sprintf(`"%s" %s`, name, sqlType)
		if cfg.Required {
			col += " NOT NULL "
		}
		if cfg.Unique {
			col += " UNIQUE"
		}
		if cfg.Default != "" {
			col += fmt.Sprintf(" DEFAULT '%s'", cfg.Default)
		}

		cols = append(cols, col)

		if cfg.PrimaryKey {
			primaryKeys = append(primaryKeys, fmt.Sprintf(`"%s"`, name))
		}
	}
	return
}
