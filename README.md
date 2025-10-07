# Xian MCP Server

A Model Context Protocol (MCP) server for interacting with the XIAN blockchain network. This server enables AI assistants to manage wallets, send transactions, query smart contracts, and interact with the XIAN blockchain and DEX.

⚠️ **IMPORTANT**: This server handles private keys and is intended for LOCAL USE ONLY. Never expose this server to the internet or use it with production wallets.

## Features

- ✅ Create new wallets (standard and HD wallets)
- ✅ Import wallets from private keys or mnemonics
- ✅ Check balances (XIAN and custom tokens)
- ✅ Send transactions and tokens
- ✅ Query and interact with smart contracts
- ✅ Sign, verify, encrypt, and decrypt messages
- ✅ Simulate transactions for gas estimation
- ✅ Query token information by symbol or contract
- ✅ Trade on the XIAN DEX (buy/sell tokens)
- ✅ Get real-time DEX price data

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

#### Option A: Using Docker Compose (Recommended)
```bash
docker-compose build
```

#### Option B: Using Docker directly
```bash
docker build -t xian-mcp-server .
```

### 3. Testing
The repo includes a test file with the proper MCP handshake that can be used to test

#### Direct test
```bash
python xian_server.py < test_requests.jsonl
```

#### Docker test
```bash
docker run --rm -i xian-mcp-server < test_requests.jsonl
```

This test validates that:
- ✅ The MCP server starts correctly and accepts stdio communication
- ✅ The MCP protocol handshake completes successfully (initialize → initialized → tools/list)
- ✅ All Python dependencies are properly installed
- ✅ The server can serialize and respond with valid JSON-RPC 2.0 messages
- ✅ All Xian blockchain tools are registered and available

You should see two JSON responses:
1. Initialize response (id:1)
2. Tools list response (id:2)

#### Implementation Tests
To test the actual Xian blockchain functionality (wallets, transactions, cryptography), run the comprehensive test suite:
```bash
# Install test dependencies
pip install pytest pytest-asyncio

# Run the tests
python test_xian_server.py
```

#### Before running the tests:
1. Open test_xian_server.py and configure the test values at the top of the file
2. Update the values with real testnet data (addresses, private keys, etc.)
3. The tests use testnet by default (https://testnet.xian.org)

#### What the tests cover:
- ✅ Wallet creation and import
- ✅ Balance and state queries
- ✅ Transaction simulation and retrieval
- ✅ Cryptographic operations - signing, encryption
- ✅ Error handling for invalid inputs

#### Expected output:
- Tests will show ✅ for passed tests
- Tests requiring configuration will be skipped with helpful messages
- Failed tests will show detailed error information

Run these tests before building the Docker container to ensure all functionality works correctly with your network configuration.

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
cp custom_catalog.yaml ~/.docker/mcp/catalogs/custom.yaml
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
- `XIAN_GRAPHQL`: GraphQL endpoint URL (default: `https://node.xian.org/graphql`)

#### Using Docker Compose with custom values

Create a `.env` file in the project directory (or copy and rename `.env.example`):
```env
XIAN_NODE_URL=https://node.xian.org
XIAN_CHAIN_ID=xian-1
XIAN_GRAPHQL=https://node.xian.org/graphql
```

Then run:
```bash
docker-compose up
```

#### Using Docker directly

To use custom values with Docker:

```json
{
  "xian": {
    "command": "docker",
    "args": [
      "run", "-i", "--rm",
      "--env", "XIAN_NODE_URL=https://your-node.example.com",
      "--env", "XIAN_CHAIN_ID=testnet-1",
      "--env", "XIAN_GRAPHQL=https://your-node.example.com/graphql",
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
- "Restore HD wallet from mnemonic: [12/24 word phrase]"

### Balance and Transactions
- "Check balance for address 8bf21c7dc3a4ff32996bf56a665e1efe3c9261cc95bbf82552c328585c863829"
- "Send 10 XIAN to [address] using private key [key]"
- "Send 100 custom_token to [address] using private key [key]"
- "Get transaction details for hash [tx_hash]"
- "Simulate sending 100 tokens to estimate gas costs"

### Smart Contracts
- "Get the source code of contract 'currency'"
- "Check the state of variable 'balances:address123' in contract 'currency'"
- "Read contract state: con_token.metadata:token_symbol"
- "Simulate calling function 'transfer' on contract 'currency'"

### Token Information
- "Find the contract address for token symbol USDT"
- "Get token metadata for contract con_my_token"
- "What's the current DEX price of con_my_token in XIAN?"

### DEX Trading
- "Buy 100 con_my_token with currency (XIAN) using private key [key]"
- "Sell 50 con_my_token for currency with 2% slippage"
- "Get the current price of con_my_token against XIAN"

### Cryptographic Operations
- "Sign the message 'Hello XIAN' with private key [key]"
- "Verify signature [sig] for message 'Hello XIAN' from address [addr]"
- "Encrypt a message from [sender_key] to [recipient_public_key]"
- "Decrypt message [encrypted] from [sender_public_key] using [receiver_private_key]"

## Available Tools

### Wallet Management

| Tool | Description | Parameters | Requires Private Key |
|------|-------------|------------|---------------------|
| `create_wallet` | Generate new random wallet | None | No |
| `create_wallet_from_private_key` | Import wallet from private key | `private_key` | Yes (to import) |
| `create_hd_wallet` | Create new HD wallet with mnemonic | None | No |
| `create_hd_wallet_from_mnemonic` | Restore HD wallet from mnemonic | `mnemonic` | No |

### Balance and Transactions

| Tool | Description | Parameters | Requires Private Key |
|------|-------------|------------|---------------------|
| `get_balance` | Check address balance | `address`, `token_contract` | No |
| `send_transaction` | Send generic transaction | `private_key`, `contract`, `function`, `kwargs` | Yes |
| `send_tokens` | Send tokens to address | `private_key`, `to_address`, `token_contract`, `amount` | Yes |
| `get_transaction` | Get transaction details | `tx_hash` | No |
| `simulate_transaction` | Estimate gas costs | `address`, `contract`, `function`, `kwargs` | No |

### Smart Contracts

| Tool | Description | Parameters | Requires Private Key |
|------|-------------|------------|---------------------|
| `get_state` | Read contract state variable | `state_key` | No |
| `get_contract` | Get contract source code | `contract_name` | No |

### Token Information

| Tool | Description | Parameters | Requires Private Key |
|------|-------------|------------|---------------------|
| `get_token_contract_by_symbol` | Find contract by token symbol | `token_symbol` | No |
| `get_token_data_by_contract` | Get token metadata | `token_contract` | No |

### DEX Operations

| Tool | Description | Parameters | Requires Private Key |
|------|-------------|------------|---------------------|
| `buy_on_dex` | Buy tokens on DEX | `private_key`, `buy_token`, `sell_token`, `amount`, `slippage`, `deadline_min` | Yes |
| `sell_on_dex` | Sell tokens on DEX | `private_key`, `sell_token`, `buy_token`, `amount`, `slippage`, `deadline_min` | Yes |
| `get_dex_price` | Get token price on DEX | `token_contract`, `base_contract` | No |

### Cryptographic Operations

| Tool | Description | Parameters | Requires Private Key |
|------|-------------|------------|---------------------|
| `sign_message` | Sign a message | `private_key`, `message` | Yes |
| `verify_signature` | Verify message signature | `address`, `message`, `signature` | No |
| `encrypt_message` | Encrypt message between parties | `sender_private_key`, `receiver_public_key`, `message` | Yes |
| `decrypt_message` | Decrypt received message | `receiver_private_key`, `sender_public_key`, `encrypted_message` | Yes |

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

## Resources

- [XIAN Network Documentation](https://docs.xian.org)
- [xian-py SDK](https://github.com/xian-network/xian-py)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [Claude Desktop MCP Guide](https://docs.anthropic.com/en/docs/mcp)
- [LM Studio MCP Documentation](https://lmstudio.ai/docs/app/plugins/mcp)

## Security Notice

This server handles sensitive cryptographic material. Always:
- Use only for local development and testing
- Never expose to the internet
- Keep private keys secure
- Use testnet for experimentation
- Verify all transactions before execution