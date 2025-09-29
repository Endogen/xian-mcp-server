# XIAN Network MCP Server

A Model Context Protocol (MCP) server that provides a secure interface for AI assistants to interact with the XIAN blockchain network.

## Purpose

This MCP server provides a secure interface for AI assistants to manage wallets, send transactions, deploy smart contracts, and interact with the XIAN blockchain network.

## Features

### Current Implementation
- **`create_wallet`** - Create a new XIAN wallet with a random seed
- **`create_wallet_from_private_key`** - Restore a wallet from an existing private key
- **`create_hd_wallet`** - Create a new HD wallet or restore from mnemonic (BIP39/BIP32 compliant)
- **`get_balance`** - Get balance for an address (XIAN or custom tokens)
- **`send_transaction`** - Send XIAN tokens to another address
- **`send_tokens`** - Send tokens from a specific contract
- **`submit_contract`** - Deploy smart contracts to the network
- **`get_state`** - Read contract state variables
- **`get_contract`** - Get and decompile contract source code
- **`simulate_transaction`** - Simulate transactions for stamp estimation or read-only execution
- **`sign_message`** - Sign messages with a wallet's private key
- **`encrypt_message`** - Encrypt messages between sender and receiver
- **`decrypt_message`** - Decrypt messages as sender or receiver

## Prerequisites

- Docker Desktop with MCP Toolkit enabled
- Docker MCP CLI plugin (`docker mcp` command)
- Access to a XIAN node (default: https://node.xian.org)

## Installation

See the step-by-step instructions provided with the files.

## Usage Examples

In Claude Desktop, you can ask:
- "Create a new XIAN wallet for me"
- "Create an HD wallet with mnemonic recovery"
- "Check the balance of address [address]"
- "Send 100 XIAN tokens to [recipient_address] using private key [key]"
- "Deploy this smart contract: [contract code]"
- "Get the state of variable 'balances' in contract 'currency'"
- "Simulate a token transfer to estimate gas costs"
- "Sign the message 'Hello XIAN' with my private key"
- "Encrypt a message from sender to receiver"
- "Decrypt this encrypted message as the receiver"

## Architecture

```
Claude Desktop → MCP Gateway → XIAN MCP Server → XIAN Network
                                     ↓
                        Docker Desktop Secrets
                        (XIAN_NODE_URL, XIAN_CHAIN_ID)
```

## Development

### Local Testing

```bash
# Set environment variables for testing
export XIAN_NODE_URL="https://node.xian.org"
export XIAN_CHAIN_ID="xian-1"

# Run directly
python xian_server.py

# Test MCP protocol
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | python xian_server.py
```

### Adding New Tools

1. Add the function to `xian_server.py`
2. Decorate with `@mcp.tool()`
3. Update the catalog entry with the new tool name
4. Rebuild the Docker image

## Environment Variables

The server supports the following environment variables:
- `XIAN_NODE_URL`: XIAN node URL (default: https://node.xian.org)
- `XIAN_CHAIN_ID`: XIAN chain ID (default: xian-1)

## Troubleshooting

### Tools Not Appearing
- Verify Docker image built successfully
- Check catalog and registry files
- Ensure Claude Desktop config includes custom catalog
- Restart Claude Desktop

### Connection Errors
- Verify XIAN_NODE_URL is accessible
- Check network connectivity
- Ensure the node is running and accepting connections

### Transaction Failures
- Verify sufficient balance for transactions
- Check that addresses are valid
- Ensure private keys are correct
- Verify contract names and function signatures

## Security Considerations

- All private keys are handled in memory only
- Never hardcode private keys in code
- Sensitive data is never logged
- Running as non-root user in Docker
- Use Docker secrets for any persistent credentials

## License

MIT License