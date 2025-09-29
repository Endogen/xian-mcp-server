#!/usr/bin/env python3
"""
Simple XIAN Network MCP Server - Interface with XIAN blockchain for wallet management and transactions
"""

import os
import sys
import logging
import json

from mcp.server.fastmcp import FastMCP
from xian_py import XianAsync, Wallet
from xian_py.crypto import encrypt, decrypt_as_sender, decrypt_as_receiver

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("xian-server")

# Try to import HDWallet if available
try:
    from xian_py.wallet import HDWallet

    HD_WALLET_AVAILABLE = True
except ImportError:
    HD_WALLET_AVAILABLE = False
    logger.warning("HDWallet not available - HD wallet features disabled")

# Initialize MCP server - NO PROMPT PARAMETER!
mcp = FastMCP("xian")

# Configuration
NODE_URL = os.environ.get("XIAN_NODE_URL", "https://node.xian.org")
CHAIN_ID = os.environ.get("XIAN_CHAIN_ID", "xian-1")


# === UTILITY FUNCTIONS ===
def format_balance(balance):
    """Format balance for display"""
    if balance is None:
        return "0"
    return str(balance)


def format_tx_result(result):
    """Format transaction result for display"""
    if result.get("success"):
        return f"✅ Transaction successful!\nTX Hash: {result.get('tx_hash', 'N/A')}\nMessage: {result.get('message', 'Transaction completed')}"
    else:
        return (
            f"❌ Transaction failed!\nError: {result.get('message', 'Unknown error')}"
        )


# === MCP TOOLS ===


@mcp.tool()
async def create_wallet() -> str:
    """Create a new XIAN wallet with a random seed."""
    logger.info("Creating new wallet")

    try:
        wallet = Wallet()
        return f"""✅ New wallet created successfully!

🔑 **Wallet Details:**
- Public Key: {wallet.public_key}
- Private Key: {wallet.private_key}

⚠️ **IMPORTANT:** Save your private key securely! It cannot be recovered if lost."""
    except Exception as e:
        logger.error(f"Error creating wallet: {e}")
        return f"❌ Error creating wallet: {str(e)}"


@mcp.tool()
async def create_wallet_from_private_key(private_key: str = "") -> str:
    """Create a wallet from an existing private key."""
    if not private_key.strip():
        return "❌ Error: Private key is required"

    logger.info("Creating wallet from private key")

    try:
        wallet = Wallet(private_key.strip())
        return f"""✅ Wallet restored successfully!

🔑 **Wallet Details:**
- Public Key: {wallet.public_key}
- Private Key: {wallet.private_key}"""
    except Exception as e:
        logger.error(f"Error creating wallet from private key: {e}")
        return f"❌ Error creating wallet from private key: {str(e)}"


@mcp.tool()
async def create_hd_wallet(mnemonic: str = "") -> str:
    """Create a new HD wallet or restore from mnemonic phrase (requires eth extras)."""
    if not HD_WALLET_AVAILABLE:
        return "❌ HD Wallet functionality not available. Install with: pip install 'xian-py[eth]'"

    logger.info("Creating HD wallet")

    try:
        if mnemonic.strip():
            # Restore from mnemonic
            hd_wallet = HDWallet(mnemonic.strip())
            message = "✅ HD wallet restored successfully!"
        else:
            # Create new HD wallet
            hd_wallet = HDWallet()
            message = "✅ New HD wallet created successfully!"

        # Get first derived wallet
        path = [44, 0, 0, 0, 0]  # m/44'/0'/0'/0'/0'
        xian_wallet = hd_wallet.get_wallet(path)

        # Try to get Ethereum wallet if eth extras are installed
        eth_info = ""
        try:
            eth_wallet = hd_wallet.get_ethereum_wallet(0)
            eth_info = f"\n\n🔷 **Ethereum Address:** {eth_wallet.public_key}"
        except:
            eth_info = "\n\n📌 Note: Ethereum address generation failed"

        return f"""{message}

📝 **Mnemonic Phrase (24 words):**
{hd_wallet.mnemonic_str}

🔑 **Derived XIAN Wallet (path: m/44'/0'/0'/0'/0'):**
- Public Key: {xian_wallet.public_key}
- Private Key: {xian_wallet.private_key}{eth_info}

⚠️ **IMPORTANT:** Save your mnemonic phrase securely! It's the only way to restore your wallet."""
    except Exception as e:
        logger.error(f"Error creating HD wallet: {e}")
        return f"❌ Error creating HD wallet: {str(e)}"


@mcp.tool()
async def get_balance(address: str = "", contract: str = "currency") -> str:
    """Get balance for an address, optionally for a specific token contract."""
    if not address.strip():
        return "❌ Error: Address is required"

    logger.info(f"Getting balance for {address}")

    try:
        async with XianAsync(NODE_URL) as xian:
            balance = await xian.get_balance(address.strip(), contract=contract.strip())

            contract_name = (
                contract.strip() if contract.strip() != "currency" else "XIAN"
            )
            return f"""💰 **Balance Information:**
- Address: {address.strip()}
- Contract: {contract_name}
- Balance: {format_balance(balance)}"""
    except Exception as e:
        logger.error(f"Error getting balance: {e}")
        return f"❌ Error getting balance: {str(e)}"


@mcp.tool()
async def send_transaction(
    private_key: str = "", to_address: str = "", amount: str = ""
) -> str:
    """Send XIAN tokens to another address."""
    if not private_key.strip():
        return "❌ Error: Private key is required"
    if not to_address.strip():
        return "❌ Error: Recipient address is required"
    if not amount.strip():
        return "❌ Error: Amount is required"

    try:
        amount_float = float(amount.strip())
        if amount_float <= 0:
            return "❌ Error: Amount must be greater than 0"
    except ValueError:
        return f"❌ Error: Invalid amount value: {amount}"

    logger.info(f"Sending transaction to {to_address}")

    try:
        wallet = Wallet(private_key.strip())
        async with XianAsync(NODE_URL, wallet=wallet) as xian:
            result = await xian.send(amount=amount_float, to_address=to_address.strip())
            return format_tx_result(result)
    except Exception as e:
        logger.error(f"Error sending transaction: {e}")
        return f"❌ Error sending transaction: {str(e)}"


@mcp.tool()
async def send_tokens(
    private_key: str = "", contract: str = "", to_address: str = "", amount: str = ""
) -> str:
    """Send tokens from a specific contract to another address."""
    if not private_key.strip():
        return "❌ Error: Private key is required"
    if not contract.strip():
        return "❌ Error: Contract name is required"
    if not to_address.strip():
        return "❌ Error: Recipient address is required"
    if not amount.strip():
        return "❌ Error: Amount is required"

    try:
        amount_float = float(amount.strip())
        if amount_float <= 0:
            return "❌ Error: Amount must be greater than 0"
    except ValueError:
        return f"❌ Error: Invalid amount value: {amount}"

    logger.info(f"Sending tokens from {contract} to {to_address}")

    try:
        wallet = Wallet(private_key.strip())
        async with XianAsync(NODE_URL, wallet=wallet) as xian:
            result = await xian.send_tx(
                contract=contract.strip(),
                function="transfer",
                kwargs={"to": to_address.strip(), "amount": amount_float},
            )
            return format_tx_result(result)
    except Exception as e:
        logger.error(f"Error sending tokens: {e}")
        return f"❌ Error sending tokens: {str(e)}"


@mcp.tool()
async def submit_contract(
    private_key: str = "",
    contract_name: str = "",
    code: str = "",
    constructor_args: str = "",
) -> str:
    """Submit a smart contract to the XIAN network."""
    if not private_key.strip():
        return "❌ Error: Private key is required"
    if not contract_name.strip():
        return "❌ Error: Contract name is required"
    if not code.strip():
        return "❌ Error: Contract code is required"

    logger.info(f"Submitting contract {contract_name}")

    try:
        wallet = Wallet(private_key.strip())

        # Parse constructor arguments if provided
        arguments = None
        if constructor_args.strip():
            try:
                arguments = json.loads(constructor_args.strip())
            except json.JSONDecodeError:
                return "❌ Error: Constructor arguments must be valid JSON"

        async with XianAsync(NODE_URL, wallet=wallet) as xian:
            if arguments:
                result = await xian.submit_contract(
                    contract_name.strip(), code.strip(), args=arguments
                )
            else:
                result = await xian.submit_contract(contract_name.strip(), code.strip())

            if result.get("success"):
                return f"""✅ Contract deployed successfully!

📋 **Deployment Details:**
- Contract Name: {contract_name.strip()}
- TX Hash: {result.get("tx_hash", "N/A")}
- Has Constructor: {"Yes" if arguments else "No"}"""
            else:
                return f"❌ Contract deployment failed: {result.get('message', 'Unknown error')}"
    except Exception as e:
        logger.error(f"Error submitting contract: {e}")
        return f"❌ Error submitting contract: {str(e)}"


@mcp.tool()
async def get_state(contract: str = "", variable: str = "", key: str = "") -> str:
    """Get state from a contract variable."""
    if not contract.strip():
        return "❌ Error: Contract name is required"
    if not variable.strip():
        return "❌ Error: Variable name is required"

    logger.info(f"Getting state for {contract}.{variable}[{key}]")

    try:
        async with XianAsync(NODE_URL) as xian:
            if key.strip():
                state = await xian.get_state(
                    contract.strip(), variable.strip(), key.strip()
                )
            else:
                state = await xian.get_state(contract.strip(), variable.strip())

            # Format the state value for display
            if isinstance(state, dict):
                state_str = json.dumps(state, indent=2)
            else:
                state_str = str(state) if state is not None else "null"

            return f"""📊 **Contract State:**
- Contract: {contract.strip()}
- Variable: {variable.strip()}
- Key: {key.strip() if key.strip() else "None"}
- Value:
{state_str}"""
    except Exception as e:
        logger.error(f"Error getting state: {e}")
        return f"❌ Error getting state: {str(e)}"


@mcp.tool()
async def get_contract(contract_name: str = "") -> str:
    """Get and decompile contract source code."""
    if not contract_name.strip():
        return "❌ Error: Contract name is required"

    logger.info(f"Getting contract {contract_name}")

    try:
        async with XianAsync(NODE_URL) as xian:
            source = await xian.get_contract(contract_name.strip(), clean=True)

            if source:
                # Truncate if too long
                if len(source) > 2000:
                    source = source[:2000] + "\n...(truncated)"

                return f"""📜 **Contract Source Code:**
Contract: {contract_name.strip()}

```python
{source}
```"""
            else:
                return f"❌ Contract '{contract_name.strip()}' not found or has no source code"
    except Exception as e:
        logger.error(f"Error getting contract: {e}")
        return f"❌ Error getting contract: {str(e)}"


@mcp.tool()
async def simulate_transaction(
    private_key: str = "", contract: str = "", function: str = "", kwargs: str = ""
) -> str:
    """Simulate a transaction to estimate stamps or execute read-only functions."""
    if not contract.strip():
        return "❌ Error: Contract name is required"
    if not function.strip():
        return "❌ Error: Function name is required"

    # Private key is optional for simulation
    sender = None
    if private_key.strip():
        try:
            wallet = Wallet(private_key.strip())
            sender = wallet.public_key
        except:
            return "❌ Error: Invalid private key"

    logger.info(f"Simulating {contract}.{function}")

    try:
        # Parse kwargs
        parsed_kwargs = {}
        if kwargs.strip():
            try:
                parsed_kwargs = json.loads(kwargs.strip())
            except json.JSONDecodeError:
                return "❌ Error: kwargs must be valid JSON"

        # Create wallet if private key provided, otherwise use a dummy wallet
        if private_key.strip():
            wallet = Wallet(private_key.strip())
        else:
            wallet = Wallet()  # Create dummy wallet for simulation

        async with XianAsync(NODE_URL, wallet=wallet) as xian:
            result = await xian.simulate(
                contract=contract.strip(),
                function=function.strip(),
                kwargs=parsed_kwargs,
            )

            return f"""🔬 **Simulation Results:**
- Contract: {contract.strip()}
- Function: {function.strip()}
- Stamps Used: {result.get("stamps_used", "N/A")}
- Success: {result.get("success", False)}
- Result: {result.get("result", "None")}
- Message: {result.get("message", "Simulation completed")}"""
    except Exception as e:
        logger.error(f"Error simulating transaction: {e}")
        return f"❌ Error simulating transaction: {str(e)}"


@mcp.tool()
async def sign_message(private_key: str = "", message: str = "") -> str:
    """Sign a message with a wallet's private key."""
    if not private_key.strip():
        return "❌ Error: Private key is required"
    if not message.strip():
        return "❌ Error: Message is required"

    logger.info("Signing message")

    try:
        wallet = Wallet(private_key.strip())
        signature = wallet.sign_msg(message.strip())

        return f"""✍️ **Message Signature:**
- Message: {message.strip()}
- Public Key: {wallet.public_key}
- Signature: {signature}

✅ The signature can be verified using the public key and original message."""
    except Exception as e:
        logger.error(f"Error signing message: {e}")
        return f"❌ Error signing message: {str(e)}"


@mcp.tool()
async def encrypt_message(
    sender_private_key: str = "", receiver_public_key: str = "", message: str = ""
) -> str:
    """Encrypt a message between sender and receiver."""
    if not sender_private_key.strip():
        return "❌ Error: Sender private key is required"
    if not receiver_public_key.strip():
        return "❌ Error: Receiver public key is required"
    if not message.strip():
        return "❌ Error: Message is required"

    logger.info("Encrypting message")

    try:
        # Validate sender private key
        sender_wallet = Wallet(sender_private_key.strip())

        # Encrypt the message
        encrypted = encrypt(
            sender_private_key.strip(), receiver_public_key.strip(), message.strip()
        )

        return f"""🔒 **Encrypted Message:**
- Sender Public Key: {sender_wallet.public_key}
- Receiver Public Key: {receiver_public_key.strip()}
- Encrypted Data: {encrypted}

ℹ️ This message can be decrypted by either the sender or receiver using their respective keys."""
    except Exception as e:
        logger.error(f"Error encrypting message: {e}")
        return f"❌ Error encrypting message: {str(e)}"


@mcp.tool()
async def decrypt_message(
    private_key: str = "",
    other_public_key: str = "",
    encrypted_message: str = "",
    as_sender: str = "false",
) -> str:
    """Decrypt a message as either sender or receiver."""
    if not private_key.strip():
        return "❌ Error: Private key is required"
    if not other_public_key.strip():
        return "❌ Error: Other party's public key is required"
    if not encrypted_message.strip():
        return "❌ Error: Encrypted message is required"

    is_sender = as_sender.strip().lower() in ["true", "yes", "1"]
    role = "sender" if is_sender else "receiver"

    logger.info(f"Decrypting message as {role}")

    try:
        # Validate private key
        wallet = Wallet(private_key.strip())

        # Decrypt based on role
        if is_sender:
            decrypted = decrypt_as_sender(
                private_key.strip(), other_public_key.strip(), encrypted_message.strip()
            )
        else:
            decrypted = decrypt_as_receiver(
                other_public_key.strip(), private_key.strip(), encrypted_message.strip()
            )

        return f"""🔓 **Decrypted Message:**
- Your Role: {role.capitalize()}
- Your Public Key: {wallet.public_key}
- Other Party's Public Key: {other_public_key.strip()}
- Decrypted Message: {decrypted}

✅ Message successfully decrypted!"""
    except Exception as e:
        logger.error(f"Error decrypting message: {e}")
        return f"❌ Error decrypting message: {str(e)}"


# === SERVER STARTUP ===
if __name__ == "__main__":
    logger.info("Starting XIAN Network MCP server...")
    logger.info(f"Node URL: {NODE_URL}")
    logger.info(f"Chain ID: {CHAIN_ID}")

    try:
        mcp.run(transport="stdio")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
