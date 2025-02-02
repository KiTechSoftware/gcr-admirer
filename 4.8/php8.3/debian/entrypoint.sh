#!/bin/sh

if [ "$1" = "auth-proxy" ]; then
    # Check if the auth-proxy binary exists
    if [ ! -f /usr/bin/auth-proxy ]; then
        echo "Error: auth-proxy binary not found in /usr/bin/"
        exit 1
    fi

    echo "Starting auth-proxy...\n"
    echo "Adminer is running on http://localhost:${ADMIRER_PORT}"
    echo "Auth-Proxy is running on http://localhost:${PROXY_PORT}"
    
    # Start PHP server for Adminer in the background
    php -S [::]:${ADMIRER_PORT} -t /var/www/html &
    # Start the authentication proxy
    auth-proxy
    
    
else
    # Execute any command provided
    exec "$@"
fi
