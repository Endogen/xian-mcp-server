# XIAN Network MCP Server - Implementation Guide

## Overview
This MCP server provides comprehensive blockchain functionality for the XIAN Network, enabling wallet management, transaction processing, smart contract deployment, and cryptographic operations.

## Architecture Details

### Core Components
1. **xian-py SDK**: Python library for XIAN blockchain interaction
2. **Async Operations**: All tools use async/await for optimal performance
3. **Connection Pooling**: XianAsync manages HTTP sessions efficiently
4. **Error Handling**: Comprehensive error catching and user-friendly messages

### Key Design Decisions

#### Async Implementation
- Uses `XianAsync` client for all blockchain operations
- Context managers ensure proper resource cleanup
- Connection pooling optimizes performance for multiple requests

#### Security Model
- Private keys handled only in memory
- No persistent storage of sensitive data
- All operations require explicit private key input
- Encryption uses Ed25519 cryptography

## Tool Specifications

### Wallet Management
- **create_wallet**: Generates Ed25519 keypair with random seed
- **create_wallet_from_private_key**: Restores wallet from 64-character hex key
- **create_hd_wallet**: BIP39/BIP32 compliant HD wallet with optional Ethereum support

### Transaction Operations
- **send_transaction**: Simple XIAN token transfer with automatic stamp calculation
- **send_tokens**: Generic token transfer for any contract implementing transfer()
- **simulate_transaction**: Pre-flight checks and read-only execution

### Contract Operations
- **submit_contract**: Deploys Python-based smart contracts
- **get_contract**: Retrieves and decompiles contract source
- **get_state**: Reads contract storage variables

### Cryptographic Features
- **sign_message**: Ed25519 message signing
- **encrypt_message**: Curve25519 encryption between parties
- **decrypt_message**: Bidirectional decryption (sender/receiver)

## Implementation Notes

### Error Handling Pattern
```python
try:
    # Validate inputs
    if not param.strip():
        return "❌ Error: Parameter required"
    
    # Execute operation
    result = await operation()
    
    # Format success response
    return f"✅ Success: {result}"
except Exception as e:
    logger.error(f"Operation failed: {e}")
    return f"❌ Error: {str(e)}"
```

### Async Context Management
```python
async with XianAsync(NODE_URL, wallet=wallet) as xian:
    # Operations here
    # Session automatically cleaned up
```

### Input Validation
- All string parameters default to empty strings
- Explicit .strip() checks prevent whitespace issues
- Numeric values parsed with try/except blocks
- JSON inputs validated before processing

## Testing Guidelines

### Unit Testing
```python
# Test wallet creation
result = await create_wallet()
assert "Public Key:" in result

# Test balance check
result = await get_balance("valid_address")
assert "Balance:" in result
```

### Integration Testing
1. Create wallet
2. Fund wallet from testnet faucet
3. Send transaction
4. Verify balance update
5. Deploy contract
6. Interact with contract

### Edge Cases
- Invalid private keys
- Malformed addresses
- Insufficient balance
- Network timeouts
- Invalid contract code

## Performance Optimization

### Connection Pooling
The XianAsync client maintains a session pool:
- Default limit: 100 connections
- DNS cache TTL: 300 seconds
- Timeouts: 15s total, 3s connect, 10s read

### Batch Operations
For multiple operations, use concurrent execution:
```python
results = await asyncio.gather(
    xian.get_balance(addr1),
    xian.get_balance(addr2),
    xian.get_state(contract, var, key)
)
```

## Common Patterns

### Transaction with Retry
```python
for attempt in range(3):
    try:
        result = await xian.send_tx(...)
        if result['success']:
            return result
    except Exception as e:
        if attempt == 2:
            raise
        await asyncio.sleep(2 ** attempt)
```

### Read-Only Simulation
```python
# No stamps required for read operations
result = await xian.simulate(
    contract="token",
    function="get_balance",
    kwargs={"address": address}
)
balance = result['result']
```

## Troubleshooting

### Common Issues
1. **"Invalid private key"**: Ensure 64-character hex string
2. **"Insufficient balance"**: Check balance before transactions
3. **"Contract not found"**: Verify contract name and deployment
4. **"Connection timeout"**: Check node URL accessibility

### Debug Mode
Enable detailed logging:
```python
logging.basicConfig(level=logging.DEBUG)
```

### Network Issues
Test connectivity:
```python
async with XianAsync(NODE_URL) as xian:
    info = await xian.get_chain_id()
    print(f"Connected to chain: {info}")
```

## Extension Points

### Adding New Tools
1. Define async function with @mcp.tool() decorator
2. Use single-line docstrings
3. Return formatted strings with emojis
4. Handle all exceptions

### Custom Token Support
Implement standard token interface:
- transfer(to, amount)
- approve(spender, amount)
- transfer_from(from, to, amount)

### Contract Standards
Follow XIAN standards (XSC001, etc.):
- Required methods and variables
- Metadata structure
- Event emission patterns

## Best Practices

### Security
- Never log private keys
- Validate all user inputs
- Use secure random for key generation
- Clear sensitive data from memory

### User Experience
- Provide clear error messages
- Use emojis for visual feedback
- Include transaction hashes in responses
- Format large numbers readably

### Code Quality
- Type hints where beneficial
- Comprehensive error handling
- Consistent naming conventions
- Detailed logging for debugging

## Resources
- [XIAN Network Docs](https://docs.xian.org)
- [xian-py GitHub](https://github.com/xian-network/xian-py)
- [Contract Standards](https://github.com/xian-network/xian-standard-contracts)
- [Testnet Faucet](https://faucet.xian.org)