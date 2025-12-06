#!/usr/bin/env python3
"""
XIAN Network MCP Server

This MCP server provides tools for interacting with the XIAN blockchain.
It enables wallet management, token operations, smart contract interactions,
and cryptographic operations.

SECURITY WARNING: This server handles private keys and should only be used locally.
Never expose this server to the internet or use it with production wallets.
"""

import os
import logging
import asyncio
from typing import Any
from decimal import Decimal

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from xian_py.wallet import Wallet
from xian_py.xian import Xian

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('xian-server')

# Configuration from environment variables
NODE_URL = os.getenv('XIAN_NODE_URL', 'https://node.xian.org')
CHAIN_ID = os.getenv('XIAN_CHAIN_ID', 'xian-1')
GRAPHQL_URL = os.getenv('XIAN_GRAPHQL', 'https://node.xian.org/graphql')

# Initialize Xian client
xian = Xian(NODE_URL, chain_id=CHAIN_ID, graphql=GRAPHQL_URL)

# Initialize MCP server
app = Server("xian-server")

logger.info("Starting XIAN Network MCP server...")
logger.info(f"Chain ID: {CHAIN_ID}")
logger.info(f"Node URL: {NODE_URL}")
logger.info(f"GraphQL : {GRAPHQL_URL}")


def format_success_response(data: dict) -> list[TextContent]:
    """
    Format a successful response in MCP format.
    Converts the data dict to a human-readable text response.
    """
    # Convert dict to formatted string
    result_text = ""
    for key, value in data.items():
        # Handle Decimal values
        if isinstance(value, Decimal):
            value = float(value)
        result_text += f"{key}: {value}\n"
    
    return [TextContent(
        type="text",
        text=result_text.strip()
    )]


def format_error_response(error_msg: str) -> list[TextContent]:
    """Format an error response in MCP format."""
    return [TextContent(
        type="text",
        text=f"Error: {error_msg}"
    )]


@app.list_tools()
async def list_tools() -> list[Tool]:
    """List all available tools."""
    return [
        # Wallet Management Tools
        Tool(
            name="create_wallet",
            description="Create a new random XIAN wallet with public/private key pair",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="create_wallet_from_private_key",
            description="Import a wallet from an existing private key",
            inputSchema={
                "type": "object",
                "properties": {
                    "private_key": {
                        "type": "string",
                        "description": "The private key (64 hex characters)"
                    }
                },
                "required": ["private_key"]
            }
        ),
        Tool(
            name="create_hd_wallet",
            description="Create a new HD (Hierarchical Deterministic) wallet with a 12-word mnemonic phrase",
            inputSchema={
                "type": "object",
                "properties": {},
                "required": []
            }
        ),
        Tool(
            name="create_hd_wallet_from_mnemonic",
            description="Restore an HD wallet from a mnemonic phrase (12 or 24 words)",
            inputSchema={
                "type": "object",
                "properties": {
                    "mnemonic": {
                        "type": "string",
                        "description": "The mnemonic phrase (12 or 24 words separated by spaces)"
                    }
                },
                "required": ["mnemonic"]
            }
        ),
        
        # Balance and Transaction Tools
        Tool(
            name="get_balance",
            description="Check the balance of a XIAN address for a specific token",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "The XIAN address to check (64 hex characters)"
                    },
                    "token_contract": {
                        "type": "string",
                        "description": "The token contract name (default: 'currency' for XIAN)",
                        "default": "currency"
                    }
                },
                "required": ["address"]
            }
        ),
        Tool(
            name="send_transaction",
            description="Send a generic transaction to execute a smart contract function",
            inputSchema={
                "type": "object",
                "properties": {
                    "private_key": {
                        "type": "string",
                        "description": "Private key of the sender"
                    },
                    "contract": {
                        "type": "string",
                        "description": "Contract name to call"
                    },
                    "function": {
                        "type": "string",
                        "description": "Function name to execute"
                    },
                    "kwargs": {
                        "type": "object",
                        "description": "Function arguments as key-value pairs",
                        "default": {}
                    }
                },
                "required": ["private_key", "contract", "function"]
            }
        ),
        Tool(
            name="send_tokens",
            description="Send tokens from one address to another",
            inputSchema={
                "type": "object",
                "properties": {
                    "private_key": {
                        "type": "string",
                        "description": "Private key of the sender"
                    },
                    "to_address": {
                        "type": "string",
                        "description": "Recipient address"
                    },
                    "token_contract": {
                        "type": "string",
                        "description": "Token contract name (default: 'currency' for XIAN)",
                        "default": "currency"
                    },
                    "amount": {
                        "type": "number",
                        "description": "Amount of tokens to send"
                    }
                },
                "required": ["private_key", "to_address", "amount"]
            }
        ),
        Tool(
            name="get_transaction",
            description="Get details of a transaction by its hash",
            inputSchema={
                "type": "object",
                "properties": {
                    "tx_hash": {
                        "type": "string",
                        "description": "Transaction hash"
                    }
                },
                "required": ["tx_hash"]
            }
        ),
        Tool(
            name="simulate_transaction",
            description="Simulate a transaction to estimate gas costs without executing it",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Sender address for simulation"
                    },
                    "contract": {
                        "type": "string",
                        "description": "Contract name"
                    },
                    "function": {
                        "type": "string",
                        "description": "Function name"
                    },
                    "kwargs": {
                        "type": "object",
                        "description": "Function arguments",
                        "default": {}
                    }
                },
                "required": ["address", "contract", "function"]
            }
        ),
        
        # Smart Contract Tools
        Tool(
            name="get_state",
            description="Read a state variable from a smart contract",
            inputSchema={
                "type": "object",
                "properties": {
                    "state_key": {
                        "type": "string",
                        "description": "State key in format 'contract.variable:key' or 'contract.variable'"
                    }
                },
                "required": ["state_key"]
            }
        ),
        Tool(
            name="get_contract",
            description="Get the source code of a smart contract",
            inputSchema={
                "type": "object",
                "properties": {
                    "contract_name": {
                        "type": "string",
                        "description": "Name of the contract"
                    }
                },
                "required": ["contract_name"]
            }
        ),
        
        # Token Information Tools
        Tool(
            name="get_token_contract_by_symbol",
            description="Find the contract address for a token by its symbol",
            inputSchema={
                "type": "object",
                "properties": {
                    "token_symbol": {
                        "type": "string",
                        "description": "Token symbol (e.g., 'USDT', 'WETH')"
                    }
                },
                "required": ["token_symbol"]
            }
        ),
        Tool(
            name="get_token_data_by_contract",
            description="Get metadata for a token by its contract address",
            inputSchema={
                "type": "object",
                "properties": {
                    "token_contract": {
                        "type": "string",
                        "description": "Token contract name"
                    }
                },
                "required": ["token_contract"]
            }
        ),
        
        # DEX Tools
        Tool(
            name="buy_on_dex",
            description="Buy tokens on the XIAN DEX",
            inputSchema={
                "type": "object",
                "properties": {
                    "private_key": {
                        "type": "string",
                        "description": "Private key for signing the transaction"
                    },
                    "buy_token": {
                        "type": "string",
                        "description": "Token contract to buy"
                    },
                    "sell_token": {
                        "type": "string",
                        "description": "Token contract to sell (usually 'currency' for XIAN)",
                        "default": "currency"
                    },
                    "amount": {
                        "type": "number",
                        "description": "Amount of sell_token to spend"
                    },
                    "slippage": {
                        "type": "number",
                        "description": "Maximum slippage percentage (e.g., 2 for 2%)",
                        "default": 2
                    },
                    "deadline_min": {
                        "type": "integer",
                        "description": "Transaction deadline in minutes from now",
                        "default": 10
                    }
                },
                "required": ["private_key", "buy_token", "amount"]
            }
        ),
        Tool(
            name="sell_on_dex",
            description="Sell tokens on the XIAN DEX",
            inputSchema={
                "type": "object",
                "properties": {
                    "private_key": {
                        "type": "string",
                        "description": "Private key for signing the transaction"
                    },
                    "sell_token": {
                        "type": "string",
                        "description": "Token contract to sell"
                    },
                    "buy_token": {
                        "type": "string",
                        "description": "Token contract to receive (usually 'currency' for XIAN)",
                        "default": "currency"
                    },
                    "amount": {
                        "type": "number",
                        "description": "Amount of sell_token to sell"
                    },
                    "slippage": {
                        "type": "number",
                        "description": "Maximum slippage percentage (e.g., 2 for 2%)",
                        "default": 2
                    },
                    "deadline_min": {
                        "type": "integer",
                        "description": "Transaction deadline in minutes from now",
                        "default": 10
                    }
                },
                "required": ["private_key", "sell_token", "amount"]
            }
        ),
        Tool(
            name="get_dex_price",
            description="Get the current price of a token on the DEX",
            inputSchema={
                "type": "object",
                "properties": {
                    "token_contract": {
                        "type": "string",
                        "description": "Token contract to get price for"
                    },
                    "base_contract": {
                        "type": "string",
                        "description": "Base token to price against (default: 'currency')",
                        "default": "currency"
                    }
                },
                "required": ["token_contract"]
            }
        ),
        
        # Cryptographic Tools
        Tool(
            name="sign_message",
            description="Sign a message with a private key",
            inputSchema={
                "type": "object",
                "properties": {
                    "private_key": {
                        "type": "string",
                        "description": "Private key to sign with"
                    },
                    "message": {
                        "type": "string",
                        "description": "Message to sign"
                    }
                },
                "required": ["private_key", "message"]
            }
        ),
        Tool(
            name="verify_signature",
            description="Verify a message signature",
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Address that allegedly signed the message"
                    },
                    "message": {
                        "type": "string",
                        "description": "Original message"
                    },
                    "signature": {
                        "type": "string",
                        "description": "Signature to verify"
                    }
                },
                "required": ["address", "message", "signature"]
            }
        ),
        Tool(
            name="encrypt_message",
            description="Encrypt a message from one party to another",
            inputSchema={
                "type": "object",
                "properties": {
                    "sender_private_key": {
                        "type": "string",
                        "description": "Sender's private key"
                    },
                    "receiver_public_key": {
                        "type": "string",
                        "description": "Receiver's public key"
                    },
                    "message": {
                        "type": "string",
                        "description": "Message to encrypt"
                    }
                },
                "required": ["sender_private_key", "receiver_public_key", "message"]
            }
        ),
        Tool(
            name="decrypt_message",
            description="Decrypt a received encrypted message",
            inputSchema={
                "type": "object",
                "properties": {
                    "receiver_private_key": {
                        "type": "string",
                        "description": "Receiver's private key"
                    },
                    "sender_public_key": {
                        "type": "string",
                        "description": "Sender's public key"
                    },
                    "encrypted_message": {
                        "type": "string",
                        "description": "Encrypted message to decrypt"
                    }
                },
                "required": ["receiver_private_key", "sender_public_key", "encrypted_message"]
            }
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool execution."""
    try:
        logger.info(f"Calling tool: {name}")
        
        # Wallet Management
        if name == "create_wallet":
            logger.info("Creating new wallet")
            wallet = Wallet()
            return format_success_response({
                "public_key": wallet.public_key,
                "private_key": wallet.private_key
            })
        
        elif name == "create_wallet_from_private_key":
            logger.info("Creating wallet from private key")
            private_key = arguments["private_key"]
            wallet = Wallet(private_key=private_key)
            return format_success_response({
                "public_key": wallet.public_key,
                "private_key": wallet.private_key
            })
        
        elif name == "create_hd_wallet":
            logger.info("Creating HD wallet")
            wallet = Wallet.generate_hd_wallet()
            return format_success_response({
                "mnemonic": wallet['mnemonic'],
                "public_key": wallet['public_key'],
                "private_key": wallet['private_key']
            })
        
        elif name == "create_hd_wallet_from_mnemonic":
            logger.info("Creating HD wallet from mnemonic")
            mnemonic = arguments["mnemonic"]
            wallet = Wallet.create_hd_wallet_from_mnemonic(mnemonic)
            return format_success_response({
                "public_key": wallet['public_key'],
                "private_key": wallet['private_key']
            })
        
        # Balance and Transactions
        elif name == "get_balance":
            address = arguments["address"]
            token_contract = arguments.get("token_contract", "currency")
            logger.info(f"Getting balance for {address}")
            
            balance = await xian.get_balance(address, token_contract)
            return format_success_response({
                "address": address,
                "token_contract": token_contract,
                "balance": balance
            })
        
        elif name == "send_transaction":
            logger.info("Sending transaction")
            private_key = arguments["private_key"]
            contract = arguments["contract"]
            function = arguments["function"]
            kwargs = arguments.get("kwargs", {})
            
            wallet = Wallet(private_key=private_key)
            tx_hash = await xian.send_transaction(
                wallet=wallet,
                contract=contract,
                function=function,
                kwargs=kwargs
            )
            return format_success_response({
                "transaction_hash": tx_hash,
                "contract": contract,
                "function": function
            })
        
        elif name == "send_tokens":
            logger.info("Sending tokens")
            private_key = arguments["private_key"]
            to_address = arguments["to_address"]
            token_contract = arguments.get("token_contract", "currency")
            amount = arguments["amount"]
            
            wallet = Wallet(private_key=private_key)
            tx_hash = await xian.send_transaction(
                wallet=wallet,
                contract=token_contract,
                function="transfer",
                kwargs={"to": to_address, "amount": amount}
            )
            return format_success_response({
                "transaction_hash": tx_hash,
                "to": to_address,
                "amount": amount,
                "token_contract": token_contract
            })
        
        elif name == "get_transaction":
            logger.info("Getting transaction details")
            tx_hash = arguments["tx_hash"]
            tx_data = await xian.get_transaction(tx_hash)
            
            # Format transaction data as string
            tx_text = f"Transaction {tx_hash}:\n"
            for key, value in tx_data.items():
                tx_text += f"{key}: {value}\n"
            
            return [TextContent(type="text", text=tx_text.strip())]
        
        elif name == "simulate_transaction":
            logger.info("Simulating transaction")
            address = arguments["address"]
            contract = arguments["contract"]
            function = arguments["function"]
            kwargs = arguments.get("kwargs", {})
            
            result = await xian.simulate_transaction(
                address=address,
                contract=contract,
                function=function,
                kwargs=kwargs
            )
            
            # Format simulation result
            result_text = f"Simulation Result:\n"
            for key, value in result.items():
                result_text += f"{key}: {value}\n"
            
            return [TextContent(type="text", text=result_text.strip())]
        
        # Smart Contracts
        elif name == "get_state":
            logger.info("Getting contract state")
            state_key = arguments["state_key"]
            value = await xian.get_state(state_key)
            return format_success_response({
                "state_key": state_key,
                "value": value
            })
        
        elif name == "get_contract":
            logger.info("Getting contract code")
            contract_name = arguments["contract_name"]
            code = await xian.get_contract(contract_name)
            return [TextContent(type="text", text=f"Contract '{contract_name}' source code:\n\n{code}")]
        
        # Token Information
        elif name == "get_token_contract_by_symbol":
            logger.info("Getting token contract by symbol")
            token_symbol = arguments["token_symbol"]
            contract = await xian.get_token_contract_by_symbol(token_symbol)
            return format_success_response({
                "token_symbol": token_symbol,
                "contract": contract
            })
        
        elif name == "get_token_data_by_contract":
            logger.info("Getting token data")
            token_contract = arguments["token_contract"]
            data = await xian.get_token_data_by_contract(token_contract)
            
            # Format token data
            token_text = f"Token Data for {token_contract}:\n"
            for key, value in data.items():
                token_text += f"{key}: {value}\n"
            
            return [TextContent(type="text", text=token_text.strip())]
        
        # DEX Operations
        elif name == "buy_on_dex":
            logger.info("Buying on DEX")
            private_key = arguments["private_key"]
            buy_token = arguments["buy_token"]
            sell_token = arguments.get("sell_token", "currency")
            amount = arguments["amount"]
            slippage = arguments.get("slippage", 2)
            deadline_min = arguments.get("deadline_min", 10)
            
            wallet = Wallet(private_key=private_key)
            tx_hash = await xian.buy_on_dex(
                wallet=wallet,
                buy_token=buy_token,
                sell_token=sell_token,
                amount=amount,
                slippage=slippage,
                deadline_min=deadline_min
            )
            return format_success_response({
                "transaction_hash": tx_hash,
                "buy_token": buy_token,
                "sell_token": sell_token,
                "amount": amount
            })
        
        elif name == "sell_on_dex":
            logger.info("Selling on DEX")
            private_key = arguments["private_key"]
            sell_token = arguments["sell_token"]
            buy_token = arguments.get("buy_token", "currency")
            amount = arguments["amount"]
            slippage = arguments.get("slippage", 2)
            deadline_min = arguments.get("deadline_min", 10)
            
            wallet = Wallet(private_key=private_key)
            tx_hash = await xian.sell_on_dex(
                wallet=wallet,
                sell_token=sell_token,
                buy_token=buy_token,
                amount=amount,
                slippage=slippage,
                deadline_min=deadline_min
            )
            return format_success_response({
                "transaction_hash": tx_hash,
                "sell_token": sell_token,
                "buy_token": buy_token,
                "amount": amount
            })
        
        elif name == "get_dex_price":
            logger.info("Getting DEX price")
            token_contract = arguments["token_contract"]
            base_contract = arguments.get("base_contract", "currency")
            
            price = await xian.get_dex_price(token_contract, base_contract)
            return format_success_response({
                "token_contract": token_contract,
                "base_contract": base_contract,
                "price": price
            })
        
        # Cryptographic Operations
        elif name == "sign_message":
            logger.info("Signing message")
            private_key = arguments["private_key"]
            message = arguments["message"]
            
            wallet = Wallet(private_key=private_key)
            signature = wallet.sign(message)
            return format_success_response({
                "message": message,
                "signature": signature,
                "public_key": wallet.public_key
            })
        
        elif name == "verify_signature":
            logger.info("Verifying signature")
            address = arguments["address"]
            message = arguments["message"]
            signature = arguments["signature"]
            
            is_valid = Wallet.verify(address, message, signature)
            return format_success_response({
                "address": address,
                "message": message,
                "signature": signature,
                "valid": is_valid
            })
        
        elif name == "encrypt_message":
            logger.info("Encrypting message")
            sender_private_key = arguments["sender_private_key"]
            receiver_public_key = arguments["receiver_public_key"]
            message = arguments["message"]
            
            sender_wallet = Wallet(private_key=sender_private_key)
            encrypted = sender_wallet.encrypt(receiver_public_key, message)
            return format_success_response({
                "encrypted_message": encrypted,
                "sender_public_key": sender_wallet.public_key
            })
        
        elif name == "decrypt_message":
            logger.info("Decrypting message")
            receiver_private_key = arguments["receiver_private_key"]
            sender_public_key = arguments["sender_public_key"]
            encrypted_message = arguments["encrypted_message"]
            
            receiver_wallet = Wallet(private_key=receiver_private_key)
            decrypted = receiver_wallet.decrypt(sender_public_key, encrypted_message)
            return format_success_response({
                "decrypted_message": decrypted,
                "sender_public_key": sender_public_key
            })
        
        else:
            return format_error_response(f"Unknown tool: {name}")
    
    except Exception as e:
        logger.error(f"Error executing tool {name}: {str(e)}")
        return format_error_response(str(e))


async def main():
    """Main entry point for the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await app.run(
            read_stream,
            write_stream,
            app.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
