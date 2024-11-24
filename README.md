[![Build Static Releases](https://github.com/quix-labs/caddy-pfx-certificates/actions/workflows/build-on-release.yml/badge.svg)](https://github.com/quix-labs/caddy-pfx-certificates/actions/workflows/build-on-release.yml)

# Caddy PFX Certificates

This repository contains a CaddyServer module for loading PFX certificates on-demand.


## Installation and Configuration

### Using Docker

- Pull the Docker image from the GitHub Container Registry:
    ```bash
    docker pull ghcr.io/quix-labs/caddy-pfx-certificates:latest
    ```

### Using xcaddy

- Before building the module, ensure you have `xcaddy` installed on your system. You can install it using the following
  command:

  ```bash
  go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest
  ```

- To build this module into Caddy, run the following command:

  ```bash
  CGO_ENABLED=1 xcaddy build --with github.com/quix-labs/caddy-pfx-certificates
  ```

  This command compiles Caddy with the image processing module included.


### Using prebuilt assets

- You can also install the tool using release assets.

  Download the appropriate package from the [Releases page](https://github.com/quix-labs/caddy-pfx-certificates/releases), and then follow the instructions provided for your specific platform.



## Usage

### Using Docker

```bash
docker run -p 80:80 -p 443:443 \
  -v $PWD/Caddyfile:/etc/caddy/Caddyfile -d \
  -v $PWD/test.pfx:/srv/test.pfx -d \
  ghcr.io/quix-labs/caddy-pfx-certificates:latest
```

Your can see more information in the [official docker documentation for caddy](https://hub.docker.com/_/caddy)

### Using xcaddy build / prebuilt assets

```bash
/path/to/your/caddy run --config /etc/caddy/Caddyfile
```

Your can see more information in the [official documentation for caddy](https://caddyserver.com/docs/build#package-support-files-for-custom-builds-for-debianubunturaspbian)


## Example Caddyfile
```plaintext

https://your-domain {
    tls {
        get_certificate pfx {
            path test.pfx
            password password
            
            # If set to false, only the certificates from the .pfx file will be sent. 
            # If set to true (default), all the intermediate certificates will be downloaded, including those up to the root CA.
            fetch_full_chain true 
        }
        
        # Or shortcut -> get_certificate pfx test.pfx password
    }
    encode zstd gzip
    root * /var/www/html
    file_server
}
```

## Development

To contribute to the development of this module, follow these steps:

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
