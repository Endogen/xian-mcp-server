#!/usr/bin/env python3
"""
XIAN Network MCP Server - Interface with XIAN blockchain for wallet management and transactions
"""

import os
import sys
import json
import aiohttp
import logging

from typing import Any
from xian_py import XianAsync, Wallet
from xian_py.wallet import HDWallet, verify_msg
from xian_py.transaction import simulate_tx_async
from xian_py.crypto import encrypt, decrypt_as_receiver
from mcp.server.fastmcp import FastMCP
from collections import defaultdict

# Configure logging to stderr
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("xian-server")

# Initialize MCP server
mcp = FastMCP("xian")

# Configuration
CHAIN_ID = os.environ.get("XIAN_CHAIN_ID", "xian-1")
NODE_URL = os.environ.get("XIAN_NODE_URL", "https://node.xian.org")
GRAPHQL = os.environ.get("XIAN_GRAPHQL", "https://node.xian.org/graphql")

# TODO: Add function to retrieve token contract from token name
# TODO: Maybe I should switch from 'address' to 'public_key'?
# TODO: Integrate DEX: 'What's the price of X on the DEX?'
# TODO: Update CLAUDE.md & README.md & test_xian_server.py
# TODO: Add docstrings

# === MCP TOOLS ===

@mcp.tool()
async def create_wallet() -> dict[str, str] | str:
    """Create a new XIAN wallet with a random seed."""

    logger.info("Creating new wallet")

    try:
        wallet = Wallet()

        return {
            "public_key": wallet.public_key,
            "private_key": wallet.private_key,
        }
    except Exception as ex:
        logger.error(f"Error creating wallet: {ex}")
        return f"❌ Error creating wallet: {str(ex)}"


@mcp.tool()
async def create_wallet_from_private_key(private_key: str = "") -> dict[str, str] | str:
    """Create a wallet from an existing private key."""

    if not private_key.strip():
        return "❌ Error: Private key is required"

    logger.info("Creating wallet from private key")

    try:
        wallet = Wallet(private_key.strip())

        return {
            "public_key": wallet.public_key,
            "private_key": wallet.private_key
        }
    except Exception as ex:
        logger.error(f"Error creating wallet from private key: {ex}")
        return f"❌ Error creating wallet from private key: {str(ex)}"


# TODO: How to best include the 'derivation_path'? Add argument?
@mcp.tool()
async def create_hd_wallet() -> dict[str, str] | str:
    """Create a new HD wallet"""

    logger.info("Creating new HD wallet")

    try:
        # Create new HD wallet
        hd_wallet = HDWallet()

        logger.info("Created new HD wallet ")

        # Get first derived wallet
        path = [44, 0, 0, 0, 0]  # m/44'/0'/0'/0'/0'
        xian_wallet = hd_wallet.get_wallet(path)
        eth_wallet = hd_wallet.get_ethereum_wallet(0)

        return {
            "mnemonic": hd_wallet.mnemonic_str,
            "path": str(path),
            "xian_public_key": xian_wallet.public_key,
            "xian_private_key": xian_wallet.private_key,
            "eth_public_key": eth_wallet.public_key,
            "eth_private_key": eth_wallet.private_key
        }
    except Exception as ex:
        logger.error(f"Error creating HD wallet: {ex}")
        return f"❌ Error creating HD wallet: {str(ex)}"


@mcp.tool()
async def create_hd_wallet_from_mnemonic(mnemonic: str = "") -> dict[str, str] | str:
    """Restore an HD wallet from mnemonic phrase"""

    if not mnemonic.strip():
        return "❌ Error: Mnemonic is required"

    logger.info("Creating HD wallet from mnemonic")

    try:
        # Restore from mnemonic
        hd_wallet = HDWallet(mnemonic.strip())
        logger.info("Created HD wallet from mnemonic")

        # Get first derived wallet
        path = [44, 0, 0, 0, 0]  # m/44'/0'/0'/0'/0'
        xian_wallet = hd_wallet.get_wallet(path)
        eth_wallet = hd_wallet.get_ethereum_wallet(0)

        return {
            "mnemonic": hd_wallet.mnemonic_str,
            "path": str(path),
            "xian_public_key": xian_wallet.public_key,
            "xian_private_key": xian_wallet.private_key,
            "eth_public_key": eth_wallet.public_key,
            "eth_private_key": eth_wallet.private_key
        }
    except Exception as ex:
        logger.error(f"Error creating HD wallet: {ex}")
        return f"❌ Error creating HD wallet: {str(ex)}"


@mcp.tool()
async def get_balance(address: str = "", token_contract: str = "currency") -> dict[str, int | float] | str:
    """Get balance for an address, optionally for a specific token contract."""

    if not address.strip():
        return "❌ Error: Address is required"

    logger.info(f"Getting balance for {address}")

    try:
        async with XianAsync(NODE_URL) as xian:
            balance = await xian.get_balance(address.strip(), contract=token_contract.strip())
            balance = 0 if balance is None else balance

            return {
                "address": address.strip(),
                "token_contract": token_contract.strip(),
                "balance": balance
            }
    except Exception as ex:
        logger.error(f"Error getting balance: {ex}")
        return f"❌ Error getting balance: {str(ex)}"


@mcp.tool()
async def send_transaction(
        private_key: str = "",
        contract: str = "",
        function: str = "",
        kwargs = None) -> dict[str, str] | str:
    """Send a transaction to the Xian Network."""

    if not private_key.strip():
        return "❌ Error: Private key is required"
    if not contract.strip():
        return "❌ Error: Private key is required"
    if not function.strip():
        return "❌ Error: Private key is required"
    if kwargs is None:
        kwargs = {}

    logger.info(f"Sending transaction")

    try:
        wallet = Wallet(private_key.strip())
        async with XianAsync(NODE_URL, wallet=wallet) as xian:
            return await xian.send_tx(contract, function, kwargs)
    except Exception as ex:
        logger.error(f"Error sending transaction: {ex}")
        return f"❌ Error sending transaction: {str(ex)}"


@mcp.tool()
async def send_tokens(
        private_key: str = "",
        to_address: str = "",
        token_contract: str = "",
        amount: float = 0) -> dict[str, str] | str:
    """Send tokens from a specific token contract to another address."""

    if not private_key.strip():
        return "❌ Error: Private key is required"
    if not token_contract.strip():
        return "❌ Error: Contract name is required"
    if not to_address.strip():
        return "❌ Error: Recipient address is required"
    if amount <= 0:
        return "❌ Error: Amount is required"

    logger.info(f"Sending {amount} {token_contract} tokens to {to_address}")

    try:
        wallet = Wallet(private_key.strip())
        async with XianAsync(NODE_URL, wallet=wallet) as xian:
            return await xian.send(amount, to_address, token_contract)
    except Exception as ex:
        logger.error(f"Error sending tokens: {ex}")
        return f"❌ Error sending tokens: {str(ex)}"


@mcp.tool()
async def get_transaction(tx_hash: str = "") -> dict[str, str] | str:
    """Retrieve transaction from a transaction hash."""

    if not tx_hash.strip():
        return "❌ Error: Transaction hash is required"

    try:
        async with XianAsync(NODE_URL) as xian:
            return await xian.get_tx(tx_hash)
    except Exception as ex:
        logger.error(f"Error retrieving transaction: {ex}")
        return f"❌ Error retrieving transaction: {str(ex)}"


@mcp.tool()
async def get_state(state_key: str) -> dict[str, Any] | str:
    """Get state from a contract variable."""

    if not state_key.strip():
        return "❌ Error: State key is required"

    logger.info(f"Getting state for key {state_key}")

    contract, _, rest = state_key.strip().partition(".")
    parts = rest.split(":")
    variable = parts[0]
    keys = tuple(parts[1:]) if len(parts) > 1 else None

    try:
        async with XianAsync(NODE_URL) as xian:
            if keys:
                state = await xian.get_state(contract, variable, *keys)
            else:
                state = await xian.get_state(contract, variable)

            if isinstance(state, dict):
                state_str = json.dumps(state, indent=2)
            else:
                state_str = str(state)

            return {
                "state_key": state_str,
                "state_value": state
            }
    except Exception as ex:
        logger.error(f"Error getting state: {ex}")
        return f"❌ Error getting state: {str(ex)}"


@mcp.tool()
async def get_contract(contract_name: str = "") -> dict[str, str] | str:
    """Get and decompile contract source code."""

    if not contract_name.strip():
        return "❌ Error: Contract name is required"

    logger.info(f"Getting contract {contract_name}")

    try:
        async with XianAsync(NODE_URL) as xian:
            source = await xian.get_contract(contract_name.strip(), clean=True)
            return {
                "contract_name": contract_name.strip(),
                "source": source
            }
    except Exception as ex:
        logger.error(f"Error getting contract: {ex}")
        return f"❌ Error getting contract: {str(ex)}"


@mcp.tool()
async def simulate_transaction(
        address: str = "",
        contract: str = "",
        function: str = "",
        kwargs = None) -> dict | str:
    """Simulate a transaction to estimate stamps or execute read-only functions."""

    if not address.strip():
        return "❌ Error: Private key is required"
    if not contract.strip():
        return "❌ Error: Private key is required"
    if not function.strip():
        return "❌ Error: Private key is required"
    if kwargs is None:
        kwargs = {}

    logger.info(f"Simulating {contract}.{function}")

    try:
        payload = {
            "contract": contract,
            "function": function,
            "kwargs": kwargs,
            "sender": address
        }

        return await simulate_tx_async(NODE_URL, payload)
    except Exception as ex:
        logger.error(f"Error simulating transaction: {ex}")
        return f"❌ Error simulating transaction: {str(ex)}"


@mcp.tool()
async def sign_message(private_key: str = "", message: str = "") -> dict[str, str] | str:
    """Sign a message with a wallet's private key."""

    if not private_key.strip():
        return "❌ Error: Private key is required"
    if not message.strip():
        return "❌ Error: Message is required"

    logger.info("Signing message")

    try:
        wallet = Wallet(private_key.strip())
        signature = wallet.sign_msg(message.strip())

        return {
            "signature": signature
        }
    except Exception as ex:
        logger.error(f"Error signing message: {ex}")
        return f"❌ Error signing message: {str(ex)}"


@mcp.tool()
async def verify_signature(address: str = "", message: str = "", signature: str = "") -> bool | str:
    """Verify a signature for a message."""

    if not address.strip():
        return "❌ Error: Address is required"
    if not message.strip():
        return "❌ Error: Address is required"
    if not signature.strip():
        return "❌ Error: Signature is required"

    logger.info("Verifying signature")

    try:
        return verify_msg(address, message, signature)
    except Exception as ex:
        logger.error(f"Error verifying signature: {ex}")
        return f"❌ Error verifying signature: {str(ex)}"


@mcp.tool()
async def encrypt_message(
        sender_private_key: str = "",
        receiver_public_key: str = "",
        message: str = "") -> dict[str, str] | str:
    """Encrypt a message between sender and receiver."""

    if not sender_private_key.strip():
        return "❌ Error: Sender private key is required"
    if not receiver_public_key.strip():
        return "❌ Error: Receiver public key is required"
    if not message.strip():
        return "❌ Error: Message is required"

    logger.info("Encrypting message")

    try:
        sender_wallet = Wallet(sender_private_key.strip())

        # Encrypt the message
        encrypted = encrypt(
            sender_private_key.strip(),
            receiver_public_key.strip(),
            message.strip()
        )

        return {
            "sender_public_key": sender_wallet.public_key.strip(),
            "receiver_public_key": receiver_public_key.strip(),
            "encrypted_message": encrypted
        }
    except Exception as ex:
        logger.error(f"Error encrypting message: {ex}")
        return f"❌ Error encrypting message: {str(ex)}"


@mcp.tool()
async def decrypt_message(
        receiver_private_key: str = "",
        sender_public_key: str = "",
        encrypted_message: str = "") -> dict[str, str] | str:
    """Decrypt a message as either sender or receiver."""

    if not receiver_private_key.strip():
        return "❌ Error: Private key is required"
    if not sender_public_key.strip():
        return "❌ Error: Other party's public key is required"
    if not encrypted_message.strip():
        return "❌ Error: Encrypted message is required"

    logger.info(f"Decrypting message")

    try:
        # Validate private key
        receiver_wallet = Wallet(receiver_private_key.strip())

        # Decrypt based on role
        decrypted = decrypt_as_receiver(
            sender_public_key.strip(),
            receiver_private_key.strip(),
            encrypted_message.strip()
        )

        return {
            "receiver_public_key": receiver_wallet.public_key.strip(),
            "sender_public_key": sender_public_key.strip(),
            "decrypted_message": decrypted
        }
    except Exception as ex:
        logger.error(f"Error decrypting message: {ex}")
        return f"❌ Error decrypting message: {str(ex)}"


@mcp.tool()
async def get_token_contract_by_symbol(token_symbol: str = "") -> dict | str:
    """Get token contract by symbol."""

    if not token_symbol.strip():
        return "❌ Error: Token symbol is required"

    try:
        tokens = await get_tokens()

        # Group contracts by symbol
        symbols = defaultdict(list)
        for tkn in tokens:
            symbols[tkn['symbol']].append(tkn['contract'])

        contracts = symbols.get(token_symbol.strip().upper(), [])

        if not contracts:
            return {
                "token_contracts": [],
                "count": 0,
                "message": "No token found with this symbol"
            }
        elif len(contracts) == 1:
            return {
                "token_contracts": contracts,
                "count": 1
            }
        else:
            return {
                "token_contracts": contracts,
                "count": len(contracts),
                "message": "Multiple tokens found with this symbol"
            }
    except Exception as ex:
        logger.error(f"Error getting token contract: {ex}")
        return f"❌ Error getting token contract: {str(ex)}"


@mcp.tool()
async def get_token_data_by_contract(token_contract: str = "") -> dict | str:
    """Get token data by contract."""

    if not token_contract.strip():
        return "❌ Error: Token contract is required"

    contract = token_contract.strip()

    query = """
    query GetTokenDetails(
      $operator: String!, 
      $logoUrl: String!, 
      $name: String!, 
      $symbol: String!, 
      $website: String!) {
      tokenStates: allStates(
        filter: {
          or: [
            { key: { equalTo: $operator } },
            { key: { equalTo: $logoUrl } },
            { key: { equalTo: $name } },
            { key: { equalTo: $symbol } },
            { key: { equalTo: $website } }
          ]
        }
      ) {
        nodes {
          key
          value
          updated
        }
      }
    }
    """

    try:
        data = await fetch_graphql(
            query=query,
            variables={
                "operator": f"{contract}.metadata:operator",
                "logoUrl": f"{contract}.metadata:token_logo_url",
                "name": f"{contract}.metadata:token_name",
                "symbol": f"{contract}.metadata:token_symbol",
                "website": f"{contract}.metadata:token_website"
            }
        )
        return data

    except Exception as ex:
        logger.error(f"Error getting token data: {ex}")
        return f"❌ Error getting token data: {str(ex)}"


@mcp.tool()
async def buy_on_dex(
        private_key: str = "",
        buy_token: str = "",
        sell_token: str = "",
        amount: float = 0,
        slippage: float = 1.0,
        deadline_min: float = 1.0) -> dict | str:
    """Buy tokens on the DEX."""

    if not private_key.strip():
        return "❌ Error: Private key is required"
    if not buy_token.strip():
        return "❌ Error: Buy token contract is required"
    if not sell_token.strip():
        return "❌ Error: Sell token contract is required"
    if amount <= 0:
        return "❌ Error: Amount must be positive"

    logger.info(f"Buying {amount} {buy_token} with {sell_token}")

    try:
        return await send_transaction(
            private_key=private_key,
            contract="con_helper_dex",
            function="buy",
            kwargs={
                "buy_token": buy_token.strip(),
                "sell_token": sell_token.strip(),
                "amount": amount,
                "slippage": slippage,
                "deadline_min": deadline_min
            }
        )
    except Exception as ex:
        logger.error(f"Error buying on DEX: {ex}")
        return f"❌ Error buying on DEX: {str(ex)}"


@mcp.tool()
async def sell_on_dex(
        private_key: str = "",
        sell_token: str = "",
        buy_token: str = "",
        amount: float = 0,
        slippage: float = 1.0,
        deadline_min: float = 1.0) -> dict | str:
    """Sell tokens on the DEX."""

    if not private_key.strip():
        return "❌ Error: Private key is required"
    if not sell_token.strip():
        return "❌ Error: Sell token contract is required"
    if not buy_token.strip():
        return "❌ Error: Buy token contract is required"
    if amount <= 0:
        return "❌ Error: Amount must be positive"

    logger.info(f"Selling {amount} {sell_token} for {buy_token}")

    try:
        return await send_transaction(
            private_key=private_key,
            contract="con_helper_dex",
            function="sell",
            kwargs={
                "sell_token": sell_token.strip(),
                "buy_token": buy_token.strip(),
                "amount": amount,
                "slippage": slippage,
                "deadline_min": deadline_min
            }
        )
    except Exception as ex:
        logger.error(f"Error selling on DEX: {ex}")
        return f"❌ Error selling on DEX: {str(ex)}"


@mcp.tool()
async def get_dex_price(token_contract: str = "", base_contract: str = "currency") -> dict | str:
    """Get DEX price for a token against a base currency."""

    if not token_contract.strip():
        return "❌ Error: Token contract is required"

    token = token_contract.strip()
    base = base_contract.strip()

    # Order tokens alphabetically (DEX convention)
    token_a, token_b = (token, base) if token < base else (base, token)

    try:
        # Get pair ID
        pair_id = await get_state(f"con_pairs.toks_to_pair:{token_a}:{token_b}")

        if pair_id.get('state_value') is None:
            return {
                "error": "Pair does not exist",
                "token": token,
                "base": base
            }

        pair = pair_id['state_value']

        # Get reserves
        reserve0 = await get_state(f"con_pairs.pairs:{pair}:reserve0")
        reserve1 = await get_state(f"con_pairs.pairs:{pair}:reserve1")

        r0 = reserve0['state_value']
        r1 = reserve1['state_value']

        # Calculate price based on token order
        if token_a == token:
            price = r1 / r0 if r0 > 0 else 0
        else:
            price = r0 / r1 if r1 > 0 else 0

        return {
            "token": token,
            "base": base,
            "price": price,
            "pair_id": pair,
            "reserve_token": r0 if token_a == token else r1,
            "reserve_base": r1 if token_a == token else r0
        }

    except Exception as ex:
        logger.error(f"Error getting DEX price: {ex}")
        return f"❌ Error getting DEX price: {str(ex)}"


# === HELPER FUNCTIONS ===

async def get_tokens() -> list[dict]:
    """Get all tokens with their contract name and symbol."""

    query = """
    query GetTokenContractsWithSymbols {
      tokenSymbols: allStates(
        filter: {
          key: { endsWith: ".metadata:token_symbol" }
        }
        orderBy: KEY_ASC
      ) {
        nodes {
          key
          value
        }
      }
      tokenContracts: allContracts(
        condition: { xsc0001: true }
      ) {
        nodes {
          name
        }
      }
    }
    """

    try:
        data = await fetch_graphql(query=query)

        # Get set of valid contract names
        valid_contracts = {
            node['name']
            for node in data['data']['tokenContracts']['nodes']
        }

        # Parse and filter tokens
        tokens = []
        for node in data['data']['tokenSymbols']['nodes']:
            contract = node['key'].split('.metadata:token_symbol')[0]
            if contract in valid_contracts:
                tokens.append({
                    'token_contract': contract.lower(),
                    'token_symbol': node['value'].upper()
                })

        return tokens

    except Exception as ex:
        logger.error(f"Error getting tokens: {ex}")
        raise


async def fetch_graphql(
        query: str,
        variables: dict = None,
        endpoint: str = None,
        headers: dict = None,
        timeout: float = 5.0) -> dict:
    """
    Execute a GraphQL query and return the results.

    Args:
        query: The GraphQL query string
        variables: Optional variables for the query
        endpoint: GraphQL endpoint URL (defaults to configured endpoint)
        headers: Optional additional headers
        timeout: Request timeout in seconds

    Returns:
        Dict containing the GraphQL response data

    Raises:
        Exception: When the query fails
    """

    variables = variables or {}
    endpoint = endpoint or GRAPHQL

    default_headers = {'Content-Type': 'application/json'}
    if headers:
        default_headers.update(headers)

    payload = {
        'query': query,
        'variables': variables
    }

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(
                    endpoint,
                    json=payload,
                    headers=default_headers,
                    timeout=aiohttp.ClientTimeout(total=timeout)
            ) as response:
                response.raise_for_status()
                result = await response.json()

                if 'errors' in result:
                    error_msg = ', '.join(ex.get('message', str(e)) for ex in result['errors'])
                    raise Exception(f"GraphQL errors: {error_msg}")

                return result.get('data', {})

        except aiohttp.ClientError as ex:
            logger.error(f"HTTP error fetching GraphQL: {ex}")
            raise Exception(f"Failed to fetch GraphQL: {str(ex)}")
        except Exception as ex:
            logger.error(f"Error fetching GraphQL: {ex}")
            raise


# === SERVER STARTUP ===

if __name__ == "__main__":
    logger.info("Starting XIAN Network MCP server...")
    logger.info(f"Chain ID: {CHAIN_ID}")
    logger.info(f"Node URL: {NODE_URL}")
    logger.info(f"GraphQL : {GRAPHQL}")

    try:
        mcp.run(transport="stdio")
    except Exception as e:
        logger.error(f"Server error: {e}", exc_info=True)
        sys.exit(1)
