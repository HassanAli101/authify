#!/usr/bin/env bash

set -e

BASE_URL="http://localhost:8080"

USERNAME="test_user123"
PASSWORD="securepassword123"

echo "================================="
echo "1️⃣ Creating user"
echo "================================="

curl -s -X POST "$BASE_URL/create-user" \
  -H "authify-username: $USERNAME" \
  -H "authify-password: $PASSWORD" \
  | tee /tmp/authify_create.out

echo ""
echo "================================="
echo "2️⃣ Generating tokens"
echo "================================="

TOKEN_RESPONSE=$(curl -s -X POST "$BASE_URL/generate-token" \
  -H "authify-username: $USERNAME" \
  -H "authify-password: $PASSWORD")

echo "$TOKEN_RESPONSE"

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep "Access Token" | awk '{print $3}')
REFRESH_TOKEN=$(echo "$TOKEN_RESPONSE" | grep "Refresh Token" | awk '{print $3}')

echo ""
echo "Extracted tokens:"
echo "ACCESS: $ACCESS_TOKEN"
echo "REFRESH: $REFRESH_TOKEN"

echo ""
echo "================================="
echo "3️⃣ Verifying token"
echo "================================="

curl -s -X POST "$BASE_URL/verify-token" \
  -H "authify-access: $ACCESS_TOKEN" \
  -H "authify-refresh: $REFRESH_TOKEN" \
  | tee /tmp/authify_verify.out

echo ""
echo "================================="
echo "4️⃣ Refreshing access token"
echo "================================="

REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/refresh-token" \
  -H "authify-access: $ACCESS_TOKEN" \
  -H "authify-refresh: $REFRESH_TOKEN")

echo "$REFRESH_RESPONSE"

echo ""
echo "================================="
echo "✅ Authify flow test complete"
echo "================================="