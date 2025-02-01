#!/bin/sh

if [ "$1" = "auth-proxy" ]; then
    # Check if the auth-proxy binary exists
    if [ ! -f /usr/bin/auth-proxy ]; then
        echo "Error: auth-proxy binary not found in /usr/bin/"
        exit 1
    fi

    # Start PHP server for Adminer in the background
    php -S [::]:3000 -t /var/www/html &

    # Start the authentication proxy
    auth-proxy
else
    # Execute any command provided
    exec "$@"
fi
