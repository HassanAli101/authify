package authify

import (
    "sync"

    "golang.org/x/crypto/bcrypt"
)

type InMemoryUserStore struct {
    mu    sync.RWMutex
    users map[string]struct {
        hashedPassword string
        role           string
    }
}

// This function initializes a new in-memory store for users
func NewInMemoryUserStore() *InMemoryUserStore {
    return &InMemoryUserStore{
        users: make(map[string]struct {
            hashedPassword string
            role           string
        }),
    }
}

// This function takes in username and password 
// It stores the username with hashed password and default "user" role in memory
// Noteworthy that the cost passed to GenerateFromPassword function is the default cost (10)
func (m *InMemoryUserStore) CreateUser(username, password string) error {
    m.mu.Lock()
    defer m.mu.Unlock()

    if _, exists := m.users[username]; exists {
        return ErrUserExists
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return err
    }

    m.users[username] = struct {
        hashedPassword string
        role           string
    }{
        hashedPassword: string(hashedPassword),
        role:           "user",
    }
    return nil
}

// This function takes in the username and password and returns role of user after validation
// uses bcrypt's CompareHashAndPassword function for password validation
func (m *InMemoryUserStore) GetUserRole(username string, password string) (string, error) {
    m.mu.RLock()
    defer m.mu.RUnlock()

    user, exists := m.users[username]
    if !exists {
        return "", ErrUserNotFound
    }

    err := bcrypt.CompareHashAndPassword([]byte(user.hashedPassword), []byte(password))
    if err != nil {
        return "", ErrInvalidPassword
    }

    return user.role, nil
}
