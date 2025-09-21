# Build Stage
FROM golang:1.23 AS builder

WORKDIR /authify

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN go build -o authify-server ./cmd/server/

# Runtime Stage
FROM gcr.io/distroless/base-debian12

WORKDIR /authify

COPY --from=builder /authify/authify-server .

EXPOSE 8080

CMD ["./authify-server"]

