A simple GUI for Cloudflare D1 built with Rust.

## Features
- Connect to Cloudflare D1 with your Bearer Token
- Connect to Cloudflare D1 with a local wrangler.toml file

## Prerequisites
- Requires Cloudflare Wrangler CLI
    - To install via Homebrew
        ```
        brew install cloudflare-wrangler2
        ```
    - Other methods coming soon

## Installation
1. Clone the repository
2. Run the command 
    ```
    cargo build
    ```
3. The binary will be in `target/release/cloudflare-d1-gui` or you can run the command
    ```
    cargo run
    ```
