# ProxyDialer

ProxyDialer is a CLI application written in Go designed to relay HTTP requests through a SOCKS5 proxy. It supports dynamic configuration reloading without needing to restart the application, based on changes to a YAML configuration file.

## Features

- **SOCKS5 Proxy Support**: Currently, only SOCKS5 proxies are supported for relaying traffic.
- **Dynamic Configuration**: Automatically reload configuration when the configuration file is modified.
- **Logging**: Logs HTTP requests and configuration changes.

## Installation

To install and run ProxyDialer, follow these steps:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/alex-pro27/proxydialer.git
   cd proxydialer
   ```

2. **Build the Application**:
   Ensure you have Go installed on your machine. If not, download and install it from the [official website](https://golang.org/dl/).

   Run the following command to build the application:
   ```bash
   go build -o proxydialer
   ```

3. **Create Configuration File**:
   Create a `config.yaml` file in the same directory as the built executable. Here is an example configuration:

   ```yaml
   version: "1.0"
   dialer:
     server: "localhost"
     port: 8080
   proxies:
     - protocol: "socks5"
       server: "socks5-server"
       port: 1080
       username: "your-username"
       password: "your-password"
       use: true
   ```

## Usage

Run the application by executing the following command in your terminal:

```bash
./proxydialer
```

By default, ProxyDialer will look for a configuration file named `config.yaml` in the current directory. You can override this by specifying the `PROXY_DEALER_CONFIG_FILE` environment variable to the desired configuration file path.

## Configuration Details

- **version**: The configuration file version.
- **dialer**: Defines the local server settings.
  - `server`: Local server address (e.g., "localhost").
  - `port`: Port where the server will listen for requests.
- **proxies**: A list of proxy server configurations.
  - `protocol`: Protocol type (Only "socks5" is supported).
  - `server`: Proxy server address.
  - `port`: Proxy server port.
  - `username`, `password`: Credentials for proxy authentication.
  - `use`: Boolean indicating whether this proxy should be used.
