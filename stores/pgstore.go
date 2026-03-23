package stores

import (
	"context"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

type AuthifyDB struct {
	conn     *pgx.Conn
	ctx      context.Context
	storeCfg StoreConfig
}

// This function takes in a connection string and a table name.
// It initializes a connection with the database, and sets its context as context.Background()
// After that, it attempts to create table if it does not exist with the passed tablename and config in the store.yml file.
// Documentation for pgx package: https://pkg.go.dev/github.com/jackc/pgx/v5
func NewAuthifyDB(connString string, cfg StoreConfig) (*AuthifyDB, error) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, connString)
	if err != nil {
		return nil, fmt.Errorf("unable to connect to database: %w", err)
	}

	db := &AuthifyDB{
		conn:     conn,
		ctx:      ctx,
		storeCfg: cfg,
	}

	if cfg.AutoCreate {
		if err = db.createTableIfNotExists(); err != nil {
			return nil, fmt.Errorf("Unable to Create Table: %w", err)
		}
	}

	log.Println("Connection with database established")
	return db, nil
}

func (db *AuthifyDB) StoreConfig() StoreConfig {
	return db.storeCfg
}

// This function takes in username and password
// It creates the username with hashed password and provided information, as per config in database
// Noteworthy that the cost passed to GenerateFromPassword function is the default cost (10)
// Documentation for bcrypt: https://pkg.go.dev/golang.org/x/crypto/bcrypt
func (db *AuthifyDB) CreateUser(data map[string]any) error {
	query, args, err := db.buildCreateUserQuery(data)
	if err != nil {
		return err
	}

	_, err = db.conn.Exec(db.ctx, query, args...)
	return err
}

func (db *AuthifyDB) buildCreateUserQuery(data map[string]any) (string, []any, error) {
	cols := make([]string, 0, len(db.storeCfg.Columns))
	args := make([]any, 0, len(db.storeCfg.Columns))
	placeholders := make([]string, 0, len(db.storeCfg.Columns))

	i := 1
	for name, cfg := range db.storeCfg.Columns {
		val, ok := data[name]

		if cfg.Required && !ok && cfg.Default == "" {
			return "", nil, fmt.Errorf("missing required field: %s", name)
		}

		if !ok {
			continue
		}

		if cfg.IsPassword {
			hash, err := bcrypt.GenerateFromPassword([]byte(val.(string)), bcrypt.DefaultCost)
			if err != nil {
				return "", nil, err
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
		db.storeCfg.Name,
		strings.Join(cols, ", "),
		strings.Join(placeholders, ", "),
	)

	return query, args, nil
}

// This function takes in the user identifier and password and returns info of user after password validation
// uses bcrypt's CompareHashAndPassword function for password validation
func (db *AuthifyDB) GetUserInfo(userIdentifier, password string) (map[string]any, error) {
	userData, err := db.fetchUserData(userIdentifier)
	if err != nil {
		return nil, err
	}

	passwordColumn := db.storeCfg.getPasswordColumnName()
	err = db.validatePassword(userData[passwordColumn].(string), password)
	if err != nil {
		return nil, err
	}

	result := make(map[string]any, len(userData))
	for name, val := range userData {
		if cfg, ok := db.storeCfg.Columns[name]; ok && !cfg.Hidden {
			result[name] = val
		}
	}

	return result, nil
}

func (db *AuthifyDB) validatePassword(userPassword, password string) error {
	if err := bcrypt.CompareHashAndPassword(
		[]byte(userPassword),
		[]byte(password),
	); err != nil {
		return ErrInvalidPassword
	}
	return nil
}

func (db *AuthifyDB) fetchUserData(userIdentifier string) (map[string]any, error) {
	selectCols := slices.Collect(maps.Keys(db.storeCfg.Columns))
	identifierColumn := db.storeCfg.getIdentifierColumnName()
	query := fmt.Sprintf(
		`SELECT %s FROM "%s" WHERE %s=$1`,
		`"`+strings.Join(selectCols, `","`)+`"`,
		db.storeCfg.Name,
		identifierColumn,
	)
	row, err := db.conn.Query(db.ctx, query, userIdentifier)
	if err != nil {
		return nil, err
	}
	data, err := pgx.CollectOneRow(
		row,
		pgx.RowToMap,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return data, nil
}

func (db *AuthifyDB) createTableIfNotExists() error {
	if !db.storeCfg.AutoCreate {
		return nil
	}

	cols, primaryKeys, err := db.constructColumnRowFromConfig(db.storeCfg.Columns)
	if err != nil {
		return err
	}

	if len(primaryKeys) > 0 {
		cols = append(cols, fmt.Sprintf("PRIMARY KEY (%s)",
			strings.Join(primaryKeys, ", ")))
	}

	query := fmt.Sprintf(
		`CREATE TABLE IF NOT EXISTS "%s" (%s);`,
		db.storeCfg.Name,
		strings.Join(cols, ", "),
	)

	_, err = db.conn.Exec(db.ctx, query)
	return err
}

func (db *AuthifyDB) constructColumnRowFromConfig(columns map[string]ColumnConfig) (cols []string, primaryKeys []string, err error) {
	for name, cfg := range db.storeCfg.Columns {
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
