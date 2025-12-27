# Authify

Authify is a lightweight authentication and authorization service written in Go.  
It provides endpoints to **create users**, **generate tokens**, **verify tokens**, and **refresh tokens**.  
The service is designed to be reusable across projects that need a simple, secure, and configurable auth system.

---

## Features

- User creation with username/password and **customizable user schema**.
- JWT-based token generation with dynamic claims.
- Token verification to check validity and extract user info.
- Token refresh mechanism for expired or near-expiry tokens.
- **Configurable database table structure** via YAML.
- **gRPC support** for inter-service communication.
- **CLI tool** for direct interaction with Authify without HTTP.
- Minimal, stateless design for easy integration.

---

## Configuration

Authify uses a **YAML configuration** file (`configs/store.yml`) to define the database schema and table behavior:

```yaml
version: 1

table:
  name: users
  auto_create: true
  columns:
    username:
      type: text
      primary_key: true
      required: true

    password:
      type: text
      required: true
      hidden: true

    role:
      type: text
      default: user
      jwt_claim: role

    email:
      type: text
      unique: true
      jwt_claim: email

    phone:
      type: text

    remember_me_days:
      type: integer
