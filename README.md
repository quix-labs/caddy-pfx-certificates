[![Build Static Releases](https://github.com/quix-labs/caddy-pfx-certificates/actions/workflows/build-on-release.yml/badge.svg)](https://github.com/quix-labs/caddy-pfx-certificates/actions/workflows/build-on-release.yml)

# Caddy PFX Certificates

This repository contains a CaddyServer module for loading PFX certificates on-demand.

## Building with xcaddy

Before building the module, ensure you have `xcaddy` installed on your system. You can install it using the following command:

```bash
go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
```

To build this module into Caddy, run the following command:

```bash
xcaddy build --with github.com/quix-labs/caddy-pfx-certificates
```

This command compiles Caddy with the PFX certificates module included.

## Usage

Follow these steps to utilize the image processing capabilities:

1. Install Caddy and libvips on your system.
2. Build Caddy with the PFX certificates module using xcaddy.
3. Configure your Caddyfile to load PFX certificates for specific routes or sites.
4. Start Caddy, and access your images with processing options via URL query parameters.

## Example Caddyfile
```plaintext
{
	on_demand_tls {
		ask http://localhost:5555/
	}
}

http://localhost:5555 {
	respond 200
}

:443 {
    tls {
        get_certificate pfx {
            path test.pfx
            password password
        }
        
        # Or shortcut -> get_certificate pfx test.pfx password
    }
    encode zstd gzip
    root * /var/www/html
    file_server
}
```

## Development

To contribute to the development of Caddy Image Processor, follow these steps:

1. Make sure you have Go installed on your system.
2. Clone this repository to your local machine:
   ```bash
   git clone https://github.com/quix-labs/caddy-pfx-certificates.git
   ```
   
3. Navigate to the project directory:
4. Install `xcaddy` if you haven't already:
    ```bash
    go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
    ```
5. Make your changes in the source code.
6. Run tests to ensure your changes haven't introduced any issues:
    ```bash
   make test
    ```
7. If tests pass, you can build the project:
    ```bash
   make build
    ```
8. To run the project in development mode, use the following command:
    ```bash
   make run
    ```
9. Once you're satisfied with your changes, create a pull request to the main branch of the repository for review.

## Credits

- [COLANT Alan](https://github.com/alancolant)
- [All Contributors](../../contributors)


## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
