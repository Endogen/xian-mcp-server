# XIAN MCP Server

A Model Context Protocol (MCP) server for interacting with the XIAN blockchain network. This server enables AI assistants to manage wallets, send transactions, deploy smart contracts, and interact with the XIAN blockchain.

⚠️ **IMPORTANT**: This server handles private keys and is intended for LOCAL USE ONLY. Never expose this server to the internet or use it with production wallets.

## Features

- ✅ Create new wallets (standard and HD wallets)
- ✅ Import wallets from private keys or mnemonics
- ✅ Check balances (XIAN and custom tokens)
- ✅ Send transactions
- ✅ Deploy and interact with smart contracts
- ✅ Sign and encrypt messages
- ✅ Simulate transactions for gas estimation

## Prerequisites

- Docker Desktop installed and running
- For Claude Desktop: Claude Desktop app (macOS, Windows, or Linux)
- For LM Studio: LM Studio version 0.3.17 or later

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/endogen/xian-mcp-server.git
cd xian-mcp-server
```

### 2. Build the Docker Container

```bash
docker build -t xian-mcp-server .
```

Or using the install script:
```bash
chmod +x install.sh
./install.sh
```

### 3. Test the Container

Verify the build was successful:
```bash
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | docker run --rm -i xian-mcp-server
```

You should see a JSON response listing all available tools.

## Installation Guide

### For Claude Desktop

#### Step 1: Configure Claude Desktop

Locate your Claude Desktop configuration file:
- **macOS**: `~/Library/Application\ Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`

#### Step 2: Add the XIAN Server

Edit the configuration file and add the XIAN server:

```json
{
  "mcpServers": {
    "xian": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "xian-mcp-server"
      ]
    }
  }
}
```

If you already have other MCP servers configured, add the "xian" entry alongside them.

#### Step 3: Restart Claude Desktop

1. Completely quit Claude Desktop (check system tray/menu bar)
2. Start Claude Desktop again
3. The XIAN tools should now be available

### For LM Studio

#### Step 1: Open MCP Configuration

1. Launch LM Studio
2. Click the **Program** tab (>_) in the right sidebar
3. Click **Install > Edit mcp.json**

#### Step 2: Add the XIAN Server

Add this configuration to your `mcp.json`:

```json
{
  "xian": {
    "command": "docker",
    "args": [
      "run",
      "-i",
      "--rm",
      "xian-mcp-server"
    ]
  }
}
```

The default location for this file is:
- **macOS/Linux**: `~/.lmstudio/mcp.json`
- **Windows**: `%USERPROFILE%\.lmstudio\mcp.json`

#### Step 3: Save and Use

Save the file - LM Studio automatically reloads MCP servers when you save changes.

### Advanced: Docker MCP Toolkit (Claude Desktop)

If you're using Docker MCP Toolkit, you can add XIAN to your custom catalog:

1. Copy the example catalog:
```bash
cp config/custom_catalog.yaml ~/.docker/mcp/catalogs/custom.yaml
```

2. Update your Claude Desktop config to use both catalogs:
```json
{
  "mcpServers": {
    "mcp-toolkit-gateway": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/var/run/docker.sock:/var/run/docker.sock",
        "-v", "~/.docker/mcp:/mcp",
        "docker/mcp-gateway",
        "--catalog=/mcp/catalogs/docker-mcp.yaml",
        "--catalog=/mcp/catalogs/custom.yaml",
        "--config=/mcp/config.yaml",
        "--registry=/mcp/registry.yaml",
        "--tools-config=/mcp/tools.yaml",
        "--transport=stdio"
      ]
    }
  }
}
```

3. Add to registry:
```bash
echo 'registry:\n  xian:\n    ref: ""' >> ~/.docker/mcp/registry.yaml
```

## Configuration

### Environment Variables

The server supports these environment variables:

- `XIAN_NODE_URL`: XIAN node URL (default: `https://node.xian.org`)
- `XIAN_CHAIN_ID`: XIAN chain ID (default: `xian-1`)

To use custom values:

```json
{
  "xian": {
    "command": "docker",
    "args": [
      "run", "-i", "--rm",
      "--env", "XIAN_NODE_URL=https://your-node.example.com",
      "--env", "XIAN_CHAIN_ID=testnet-1",
      "xian-mcp-server"
    ]
  }
}
```

## Usage Examples

Once installed, you can interact with the XIAN blockchain through your AI assistant:

### Basic Wallet Operations
- "Create a new XIAN wallet"
- "Create an HD wallet with recovery phrase"
- "Import wallet from private key [key]"

### Balance and Transactions
- "Check balance for address 8bf21c7dc3a4ff32996bf56a665e1efe3c9261cc95bbf82552c328585c863829"
- "Send 10 XIAN to [address] using private key [key]"
- "Simulate sending 100 tokens to estimate gas costs"

### Smart Contracts
- "Deploy this contract: @export def hello(): return 'world'"
- "Get the source code of contract 'currency'"
- "Check the state of variable 'balances' in contract 'currency'"

### Cryptographic Operations
- "Sign the message 'Hello XIAN' with private key [key]"
- "Encrypt a message from [sender_key] to [recipient_public_key]"

## Security Considerations

⚠️ **CRITICAL SECURITY INFORMATION**:

1. **This server is for LOCAL USE ONLY** - Never expose it to the internet
2. **Use test wallets only** - Never use production wallets for testing
3. **Private keys are handled in memory** - They are never stored or logged
4. **Each tool requires explicit approval** - Both Claude and LM Studio will ask for confirmation before executing tools
5. **Run in Docker** - The server runs in an isolated container for security

### Best Practices

- Generate new test wallets for experimentation
- Use testnet nodes when available
- Never commit private keys to version control
- Review all transaction parameters before approval
- Keep the Docker image updated

## Available Tools

| Tool | Description | Requires Private Key |
|------|-------------|---------------------|
| `create_wallet` | Generate new wallet | No |
| `create_wallet_from_private_key` | Import existing wallet | Yes (to import) |
| `create_hd_wallet` | Create/restore HD wallet | No |
| `get_balance` | Check address balance | No |
| `send_transaction` | Send XIAN tokens | Yes |
| `send_tokens` | Send custom tokens | Yes |
| `submit_contract` | Deploy smart contract | Yes |
| `get_state` | Read contract state | No |
| `get_contract` | Get contract source | No |
| `simulate_transaction` | Estimate gas costs | No |
| `sign_message` | Sign a message | Yes |
| `encrypt_message` | Encrypt between parties | Yes |
| `decrypt_message` | Decrypt messages | Yes |

## Troubleshooting

### Container won't build
- Ensure Docker Desktop is running
- Check that you have sufficient disk space
- Try `docker system prune` to clean up old images

### Tools don't appear in Claude/LM Studio
- Verify the container built successfully: `docker images | grep xian`
- Check the config file syntax (must be valid JSON)
- Ensure you completely restarted the application
- Test the container directly: `docker run --rm xian-mcp-server`

### Connection errors
- Verify the XIAN node URL is accessible
- Check your internet connection
- Try the default node: `https://node.xian.org`

### Permission denied errors
- On Linux/macOS: Ensure Docker has necessary permissions
- On Windows: Run Docker Desktop as administrator if needed

## Development

### Running without Docker

For development, you can run the server directly:

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python xian_server.py
```

### Running tests

```bash
# Test the MCP protocol implementation
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python xian_server.py
```

## Resources

- [XIAN Network Documentation](https://docs.xian.org)
- [xian-py SDK](https://github.com/xian-network/xian-py)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [Claude Desktop MCP Guide](https://docs.anthropic.com/en/docs/mcp)
- [LM Studio MCP Documentation](https://lmstudio.ai/docs/app/plugins/mcp)
