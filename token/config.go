package token

import (
	"time"
)

type TokenConfig struct {
	Issuer       string            `yaml:"issuer"`
	AccessToken  AccessTokenConfig `yaml:"access_token"`
	RefreshToken RefreshTokenConfig `yaml:"refresh_token"`
}

type AccessTokenConfig struct {
	Duration      time.Duration          `yaml:"duration"`
	SigningMethod string                 `yaml:"signing_method"`
	Claims        map[string]ClaimConfig `yaml:"claims"`
}

type RefreshTokenConfig struct {
	Duration         time.Duration          `yaml:"duration"`
	AbsoluteDuration time.Duration          `yaml:"absolute_duration"`
	Claims           map[string]ClaimConfig `yaml:"claims"`
}

type ClaimConfig struct {
	Source string `yaml:"source"` // db | request | system
	Column string `yaml:"column,omitempty"`
	Header string `yaml:"header,omitempty"`
	Type   string `yaml:"type,omitempty"`
	Value  any    `yaml:"value,omitempty"`
	IsIdentifier bool   `yaml:"is_identifier,omitempty"`
}
