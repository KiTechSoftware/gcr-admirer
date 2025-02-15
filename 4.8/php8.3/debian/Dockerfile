# Stage 1: Build the Go authentication proxy
FROM golang:latest AS builder

WORKDIR /app

# Copy Go files
COPY go.mod go.sum ./
RUN go mod download

COPY main.go .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o auth-proxy main.go

# Stage 2: Create the final image
FROM ghcr.io/kitechsoftware/php:8.3-cli-debian

WORKDIR /var/www/html

# Install system dependencies and PHP extensions
RUN apt-get update && apt-get install -y \
        libfreetype-dev \
        libjpeg62-turbo-dev \
        libpng-dev \
        libpq-dev \
        libsqlite3-dev \
        libmariadb-dev-compat \
        libmariadb-dev \
        libonig-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd \
    && docker-php-ext-install pdo pdo_mysql pdo_pgsql pdo_sqlite

RUN docker-php-ext-install mysqli

# Copy compiled binary from builder
COPY --from=builder /app/auth-proxy /usr/bin/auth-proxy

# Copy entrypoint script and index.php
COPY entrypoint.sh hash-pass /usr/bin/
COPY index.php ./

# Make scripts executable
RUN chmod +x /usr/bin/auth-proxy /usr/bin/hash-pass /usr/bin/entrypoint.sh

# Expose ports
EXPOSE 3000 8080

# Set environment variables
ENV ADMIRER_PORT=3000
ENV PROXY_PORT=80
ENV ADMIN_USERNAME=admin
ENV ADMIN_PASSWORD_HASH='$2a$10$3HW9I1Jgby.ah0ZrI0XmR.IhaTnX85KBUzN0hh7UFhk20u1OW51YC'
ENV ADMIRER_VERSION=4.8.1
ENV PHP_VERSION=8.3

# Start both PHP server for Adminer and the Go authentication proxy
ENTRYPOINT ["/usr/bin/entrypoint.sh"]

CMD ["auth-proxy"]
