package stores

import (
	"sync"

	"golang.org/x/crypto/bcrypt"
)

// InMemoryUserStore is a config-driven, in-memory implementation of Store
type InMemoryUserStore struct {
	mu       sync.RWMutex
	users    map[string]map[string]string
	tableCfg TableConfig
}

// NewInMemoryUserStore initializes a new in-memory store using table config
func NewInMemoryUserStore(cfg TableConfig) *InMemoryUserStore {
	return &InMemoryUserStore{
		users:    make(map[string]map[string]string),
		tableCfg: cfg,
	}
}

// TableConfig exposes the schema config
func (m *InMemoryUserStore) TableConfig() TableConfig {
	return m.tableCfg
}

// CreateUser creates a user using dynamic fields defined in config
func (m *InMemoryUserStore) CreateUser(data map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	username, ok := data["username"]
	if !ok {
		return ErrUserNotFound
	}

	if _, exists := m.users[username]; exists {
		return ErrUserExists
	}

	user := make(map[string]string)

	for name, cfg := range m.tableCfg.Columns {
		val, ok := data[name]

		if cfg.Required && !ok && cfg.Default == "" {
			return ErrInvalidPassword
		}

		if !ok {
			if cfg.Default != "" {
				val = cfg.Default
			} else {
				continue
			}
		}

		if name == "password" {
			hash, err := bcrypt.GenerateFromPassword([]byte(val), bcrypt.DefaultCost)
			if err != nil {
				return err
			}
			val = string(hash)
		}

		user[name] = val
	}

	m.users[username] = user
	return nil
}

// GetUserInfo authenticates and returns non-hidden user fields
func (m *InMemoryUserStore) GetUserInfo(username, password string) (map[string]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.users[username]
	if !exists {
		return nil, ErrUserNotFound
	}

	hashed, ok := user["password"]
	if !ok {
		return nil, ErrInvalidPassword
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashed), []byte(password)); err != nil {
		return nil, ErrInvalidPassword
	}

	result := make(map[string]string)
	for name, cfg := range m.tableCfg.Columns {
		if cfg.Hidden {
			continue
		}
		if val, ok := user[name]; ok {
			result[name] = val
		}
	}

	return result, nil
}
