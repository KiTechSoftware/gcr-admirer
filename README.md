# GCR Admirer

A custom admirer using PHP 8.3, as development on the original project seems to have stopped.

## Running the Container

To run the container, use the following command:

```sh
docker run -d -p 8080:8080 \
    -e ADMIN_USERNAME=admin \
    -e ADMIN_PASSWORD_HASH='$2a$10$EjCXp5hIwLw5uo2T6I0q0.NjM/a/1ZW2wTy4xv6blPrGIk4QOkgbi' \
    adminer-auth-proxy
```

## Generating a Password Hash

To generate a password hash, use the following command:

```sh
docker run --rm -i gcradmirer hash-pass
```

## Default Credentials

The default username and password are both `admin`.

## Bypassing the Proxy

If you want to bypass the proxy, simply expose port 3000.

