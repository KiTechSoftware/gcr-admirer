# Stage 1: Build the Go authentication proxy
FROM golang:latest AS builder

WORKDIR /app

# Copy Go files
COPY go.mod go.sum ./
RUN go mod download

COPY main.go .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o auth-proxy main.go

# Stage 2: Create a minimal production image
FROM ghcr.io/kitechsoftware/php:8.3-cli-alpine

WORKDIR /var/www/html

# Install necessary packages
# RUN apk add --no-cache \
#     ca-certificates \
#     curl \
#     unzip \
#     php-cli \
#     php-mysql \
#     php-pgsql \
#     php-sqlite3 \
#     php-simplexml \
#     php-json \
#     php-xml \
#     php-curl \
#     php-zip \
#     php-bcmath \
#     php-gd \
#     php-intl \
#     php-mbstring \
#     php-soap \
#     php-redis \
#     php-mongodb \
#     php-elasticsearch \
#     php-interbase \
#     php-oci8 \
#     php-pdo-dblib

# Copy compiled binary from builder
COPY --from=builder /app/auth-proxy /usr/bin/auth-proxy

# Copy entrypoint script and index.php
COPY entrypoint.sh hash-pass /usr/bin/
COPY index.php generate_bcrypt_hash.php ./

# Make scripts executable
RUN chmod +x /usr/bin/auth-proxy /usr/bin/hash-pass /usr/bin/entrypoint.sh

# Expose ports
EXPOSE 80 3000

# Set environment variables
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD_HASH='$2y$10$OwWQ3.cAZleLvfSzl8fw2.O0pjee8T9fkrLPr/K1z71BV7e1pK.Ye'
ENV ADMIRER_VERSION=4.8.1
ENV PHP_VERSION=8.3


# Start both PHP server for Adminer and the Go authentication proxy
ENTRYPOINT ["/usr/bin/entrypoint.sh"]

CMD ["auth-proxy"]