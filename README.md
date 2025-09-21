# Authify

Authify is a lightweight authentication and authorization service written in Go.  
It provides endpoints to **create users**, **generate tokens**, **verify tokens**, and **refresh tokens**.  
The service is designed to be reusable across future projects that need a simple and secure way to handle auth.  

---

## Features
- User creation with username/password.
- JWT-based token generation.
- Token verification to check validity and extract user role.
- Token refresh mechanism for expired or near-expiry tokens.
- Minimal, stateless design for easy integration with any project.

---

## Endpoints
- `POST /createUser` → Create a new user with username and password.  
- `POST /generateToken` → Generate a JWT token for a valid user.  
- `POST /verifyToken` → Verify if a JWT token is valid and retrieve user info.  
- `POST /refreshToken` → Refresh an existing JWT token.

---

### Prerequisites
- Go 1.23+
- PostgreSQL (or whichever DB you configure in `.env`)