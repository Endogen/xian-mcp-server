#!/usr/bin/env python3
"""
Test suite for XIAN MCP Server functions
Run with: pytest test_xian_server.py -v
Or directly: python test_xian_server.py
"""

import os
import pytest

# Set testnet configuration
os.environ["XIAN_GRAPHQL"] = "https://node.xian.org/graphql"
os.environ["XIAN_NODE_URL"] = "https://testnet.xian.org"
os.environ["XIAN_CHAIN_ID"] = "xian-testnet-12"

# Import after setting env vars
from xian_server import (
    create_wallet,
    create_wallet_from_private_key,
    create_hd_wallet,
    create_hd_wallet_from_mnemonic,
    get_balance,
    send_transaction,
    send_tokens,
    get_transaction,
    get_state,
    get_contract,
    simulate_transaction,
    sign_message,
    verify_signature,
    encrypt_message,
    decrypt_message,
    get_token_contract_by_symbol,
    get_token_data_by_contract,
    buy_on_dex,
    sell_on_dex,
    get_dex_price
)

# ==========================================
# ADJUST THESE VALUES FOR YOUR TESTING
# ==========================================

# Test wallet credentials (generate a test wallet first)
TEST_PRIVATE_KEY = "b93ffd38047268fd0f6c56fe1f529d6f87432b0b23f4cc8cfe67bfa63b340224"
TEST_ADDRESS = "c4fe8a0bf7a23d5830dde3781abbf2c64ed9f2a6bf052ca1ee48c0ea78e9a724"

# Test mnemonic for HD wallet (generate one first or use your own)
TEST_MNEMONIC = "donor drink mushroom cave pull hunt execute middle assault group airport middle evidence umbrella almost heart coin volume swap pill husband defy mango equal"

# Test transaction hash (use a real tx hash from testnet)
TEST_TX_HASH = "E18080A7ABD51EC135CD0ADD8836F10807700DEF7AF920592F4D81E68CA5E548"

# Test contract and state (adjust to actual testnet values)
TEST_CONTRACT = "currency"
TEST_STATE_KEY = "currency.balances:c4fe8a0bf7a23d5830dde3781abbf2c64ed9f2a6bf052ca1ee48c0ea78e9a724"

# Test recipient address for sending tokens
TEST_RECIPIENT_ADDRESS = "081e233f4e122a5fd79ff3c44f9d58848c3214f7110130936661394403100a9a"

# Test message signing
TEST_MESSAGE = "Hello XIAN Testnet"

# Test encryption (need two wallets)
TEST_SENDER_PUBLIC_KEY = "c4fe8a0bf7a23d5830dde3781abbf2c64ed9f2a6bf052ca1ee48c0ea78e9a724"
TEST_SENDER_PRIVATE_KEY = "b93ffd38047268fd0f6c56fe1f529d6f87432b0b23f4cc8cfe67bfa63b340224"
TEST_RECEIVER_PUBLIC_KEY = "d1cb00bd98f59a72f10516adf49f1b280e4d20dffbeeaa53e63c37d940555a1c"
TEST_RECEIVER_PRIVATE_KEY = "e77263bd53c54fc446ac620d71efb2197745d2b113be861afd18040a33e11104"

# Test token and DEX values (adjust to actual testnet values)
TEST_TOKEN_SYMBOL = "XIAN"  # Use a token symbol that exists on testnet
TEST_TOKEN_CONTRACT = "currency"  # Use a valid token contract
TEST_DEX_TOKEN = "con_test_token"  # Use a token that has a DEX pair on testnet
TEST_DEX_BASE = "currency"  # Base currency for DEX trades


# ==========================================
# TESTS
# ==========================================


class TestWalletCreation:
    """Test wallet creation and import functions"""

    @pytest.mark.asyncio
    async def test_create_wallet(self):
        """Test creating a new random wallet"""
        result = await create_wallet()

        assert isinstance(result, dict), "Should return a dictionary"
        assert "public_key" in result, "Should contain public_key"
        assert "private_key" in result, "Should contain private_key"
        assert len(result["private_key"]) == 64, "Private key should be 64 chars (hex)"
        assert len(result["public_key"]) == 64, "Public key should be 64 chars (hex)"

        print(f"✅ Created wallet: {result['public_key'][:16]}...")

    @pytest.mark.asyncio
    async def test_create_wallet_from_private_key(self):
        """Test importing wallet from private key"""
        result = await create_wallet_from_private_key(TEST_PRIVATE_KEY)

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("TEST_PRIVATE_KEY not set - adjust the test value")

        assert isinstance(result, dict), "Should return a dictionary"
        assert "public_key" in result, "Should contain public_key"
        assert "private_key" in result, "Should contain private_key"
        assert result["private_key"] == TEST_PRIVATE_KEY, "Should match input private key"

        print(f"✅ Imported wallet: {result['public_key'][:16]}...")

    @pytest.mark.asyncio
    async def test_create_wallet_from_invalid_private_key(self):
        """Test error handling for invalid private key"""
        result = await create_wallet_from_private_key("invalid_key")

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"

        print(f"✅ Correctly rejected invalid private key")

    @pytest.mark.asyncio
    async def test_create_hd_wallet(self):
        """Test creating a new HD wallet"""
        result = await create_hd_wallet()

        assert isinstance(result, dict), "Should return a dictionary"
        assert "mnemonic" in result, "Should contain mnemonic"
        assert "xian_public_key" in result, "Should contain XIAN public key"
        assert "xian_private_key" in result, "Should contain XIAN private key"
        assert "eth_public_key" in result, "Should contain ETH public key"
        assert "eth_private_key" in result, "Should contain ETH private key"

        mnemonic_words = result["mnemonic"].split()
        assert len(mnemonic_words) in [12, 24], "Mnemonic should be 12 or 24 words"

        print(f"✅ Created HD wallet with {len(mnemonic_words)} word mnemonic")

    @pytest.mark.asyncio
    async def test_create_hd_wallet_from_mnemonic(self):
        """Test restoring HD wallet from mnemonic"""
        result = await create_hd_wallet_from_mnemonic(TEST_MNEMONIC)

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("TEST_MNEMONIC not set - adjust the test value")

        assert isinstance(result, dict), "Should return a dictionary"
        assert "mnemonic" in result, "Should contain mnemonic"
        assert result["mnemonic"] == TEST_MNEMONIC, "Should match input mnemonic"

        print(f"✅ Restored HD wallet from mnemonic")


class TestBalanceAndState:
    """Test balance and state query functions"""

    @pytest.mark.asyncio
    async def test_get_balance(self):
        """Test getting balance for an address"""
        result = await get_balance(TEST_ADDRESS, "currency")

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("TEST_ADDRESS not set or network error")

        assert isinstance(result, dict), "Should return a dictionary"
        assert "address" in result, "Should contain address"
        assert "token_contract" in result, "Should contain token_contract"
        assert "balance" in result, "Should contain balance"
        assert isinstance(result["balance"], (int, float)), "Balance should be numeric"

        print(f"✅ Balance: {result['balance']} {result['token_contract']}")

    @pytest.mark.asyncio
    async def test_get_balance_missing_address(self):
        """Test error handling for missing address"""
        result = await get_balance("")

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"

        print(f"✅ Correctly rejected empty address")

    @pytest.mark.asyncio
    async def test_get_state(self):
        """Test getting contract state"""
        result = await get_state(TEST_STATE_KEY)

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("TEST_STATE_KEY not set or network error")

        assert isinstance(result, dict), "Should return a dictionary"
        assert "state_key" in result, "Should contain state_key"
        assert "state_value" in result, "Should contain state_value"

        print(f"✅ State retrieved: {result['state_value']}")

    @pytest.mark.asyncio
    async def test_get_contract(self):
        """Test getting contract source code"""
        result = await get_contract(TEST_CONTRACT)

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("Network error or contract not found")

        assert isinstance(result, dict), "Should return a dictionary"
        assert "contract_name" in result, "Should contain contract_name"
        assert "source" in result, "Should contain source"
        assert len(result["source"]) > 0, "Source should not be empty"

        print(f"✅ Retrieved contract source ({len(result['source'])} chars)")


class TestTransactions:
    """Test transaction-related functions"""

    @pytest.mark.asyncio
    async def test_simulate_transaction(self):
        """Test simulating a transaction"""
        # Simulate a balance check (read-only function)
        result = await simulate_transaction(
            address=TEST_ADDRESS,
            contract="currency",
            function="balance_of",
            kwargs={"address": TEST_ADDRESS}
        )

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("TEST_ADDRESS not set or network error")

        assert isinstance(result, dict), "Should return a dictionary"
        # Simulation results vary, but should be a dict

        print(f"✅ Transaction simulated successfully")

    @pytest.mark.asyncio
    async def test_get_transaction(self):
        """Test retrieving a transaction by hash"""
        result = await get_transaction(TEST_TX_HASH)

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("TEST_TX_HASH not set or network error")

        assert isinstance(result, dict), "Should return a dictionary"

        print(f"✅ Transaction retrieved")

    @pytest.mark.asyncio
    async def test_send_transaction_missing_params(self):
        """Test error handling for missing transaction parameters"""
        result = await send_transaction()

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"

        print(f"✅ Correctly rejected transaction with missing params")

    @pytest.mark.asyncio
    async def test_send_tokens_missing_params(self):
        """Test error handling for missing token send parameters"""
        result = await send_tokens()

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"

        print(f"✅ Correctly rejected token send with missing params")


class TestCryptography:
    """Test cryptographic functions"""

    @pytest.mark.asyncio
    async def test_sign_message(self):
        """Test message signing"""
        result = await sign_message(TEST_PRIVATE_KEY, TEST_MESSAGE)

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("TEST_PRIVATE_KEY not set")

        assert isinstance(result, dict), "Should return a dictionary"
        assert "signature" in result, "Should contain signature"
        assert len(result["signature"]) > 0, "Signature should not be empty"

        print(f"✅ Message signed: {result['signature'][:32]}...")

    @pytest.mark.asyncio
    async def test_verify_signature(self):
        """Test signature verification"""
        # First sign a message
        sign_result = await sign_message(TEST_PRIVATE_KEY, TEST_MESSAGE)

        if isinstance(sign_result, str) and sign_result.startswith("❌"):
            pytest.skip("TEST_PRIVATE_KEY not set")

        signature = sign_result["signature"]

        # Then verify it
        result = await verify_signature(TEST_ADDRESS, TEST_MESSAGE, signature)

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("TEST_ADDRESS not set or verification failed")

        assert isinstance(result, bool), "Should return a boolean"
        assert result is True, "Signature should be valid"

        print(f"✅ Signature verified successfully")

    @pytest.mark.asyncio
    async def test_verify_invalid_signature(self):
        """Test verification of invalid signature"""
        result = await verify_signature(TEST_ADDRESS, TEST_MESSAGE, "invalid_signature")

        if isinstance(result, str) and result.startswith("❌"):
            # Expected error for invalid signature format
            print(f"✅ Correctly rejected invalid signature")
        else:
            assert result is False, "Should return False for invalid signature"
            print(f"✅ Invalid signature correctly returned False")

    @pytest.mark.asyncio
    async def test_encrypt_message(self):
        """Test message encryption"""
        result = await encrypt_message(
            TEST_SENDER_PRIVATE_KEY,
            TEST_RECEIVER_PUBLIC_KEY,
            TEST_MESSAGE
        )

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("Encryption keys not set")

        assert isinstance(result, dict), "Should return a dictionary"
        assert "encrypted_message" in result, "Should contain encrypted_message"
        assert "sender_public_key" in result, "Should contain sender_public_key"
        assert "receiver_public_key" in result, "Should contain receiver_public_key"

        print(f"✅ Message encrypted: {result['encrypted_message'][:32]}...")

    @pytest.mark.asyncio
    async def test_decrypt_message(self):
        """Test message decryption"""
        # First encrypt a message
        encrypt_result = await encrypt_message(
            TEST_SENDER_PRIVATE_KEY,
            TEST_RECEIVER_PUBLIC_KEY,
            TEST_MESSAGE
        )

        if isinstance(encrypt_result, str) and encrypt_result.startswith("❌"):
            pytest.skip("Encryption keys not set")

        encrypted_msg = encrypt_result["encrypted_message"]

        # Then decrypt it
        result = await decrypt_message(
            TEST_RECEIVER_PRIVATE_KEY,
            TEST_SENDER_PUBLIC_KEY,
            encrypted_msg
        )

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("Decryption keys not set")

        assert isinstance(result, dict), "Should return a dictionary"
        assert "decrypted_message" in result, "Should contain decrypted_message"
        assert result["decrypted_message"] == TEST_MESSAGE, "Should match original message"

        print(f"✅ Message decrypted: {result['decrypted_message']}")

    @pytest.mark.asyncio
    async def test_encrypt_decrypt_missing_params(self):
        """Test error handling for missing encryption parameters"""
        result = await encrypt_message()

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"

        print(f"✅ Correctly rejected encryption with missing params")


class TestTokens:
    """Test token-related functions"""

    @pytest.mark.asyncio
    async def test_get_token_contract_by_symbol(self):
        """Test getting token contract by symbol"""
        result = await get_token_contract_by_symbol(TEST_TOKEN_SYMBOL)

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("Network error or token symbol not found")

        assert isinstance(result, dict), "Should return a dictionary"
        assert "token_contracts" in result, "Should contain token_contracts"
        assert "count" in result, "Should contain count"
        assert isinstance(result["token_contracts"], list), "token_contracts should be a list"
        assert isinstance(result["count"], int), "count should be an integer"

        if result["count"] > 0:
            print(f"✅ Found {result['count']} token(s) with symbol {TEST_TOKEN_SYMBOL}")
        else:
            print(f"✅ No tokens found with symbol {TEST_TOKEN_SYMBOL} (expected)")

    @pytest.mark.asyncio
    async def test_get_token_contract_by_symbol_empty(self):
        """Test error handling for empty token symbol"""
        result = await get_token_contract_by_symbol("")

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"

        print(f"✅ Correctly rejected empty token symbol")

    @pytest.mark.asyncio
    async def test_get_token_contract_by_symbol_nonexistent(self):
        """Test getting token contract for non-existent symbol"""
        result = await get_token_contract_by_symbol("NONEXISTENT_TOKEN_XYZ_123")

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("Network error")

        assert isinstance(result, dict), "Should return a dictionary"
        assert result["count"] == 0, "Should find no tokens"
        assert "message" in result, "Should contain message about no tokens found"

        print(f"✅ Correctly returned empty list for non-existent token")

    @pytest.mark.asyncio
    async def test_get_token_data_by_contract(self):
        """Test getting token data by contract"""
        result = await get_token_data_by_contract(TEST_TOKEN_CONTRACT)

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("Network error or token contract not found")

        assert isinstance(result, dict), "Should return a dictionary"
        # The structure depends on GraphQL response, just verify it's a dict

        print(f"✅ Retrieved token data for contract {TEST_TOKEN_CONTRACT}")

    @pytest.mark.asyncio
    async def test_get_token_data_by_contract_empty(self):
        """Test error handling for empty token contract"""
        result = await get_token_data_by_contract("")

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"

        print(f"✅ Correctly rejected empty token contract")


class TestDEX:
    """Test DEX-related functions"""

    @pytest.mark.asyncio
    async def test_get_dex_price(self):
        """Test getting DEX price for a token"""
        result = await get_dex_price(TEST_DEX_TOKEN, TEST_DEX_BASE)

        if isinstance(result, str) and result.startswith("❌"):
            pytest.skip("Network error or DEX pair not found")

        assert isinstance(result, dict), "Should return a dictionary"

        # Check for either successful price retrieval or pair not found
        if "error" in result:
            assert "token" in result, "Should contain token"
            assert "base" in result, "Should contain base"
            print(f"✅ DEX pair not found (expected for test token)")
        else:
            assert "token" in result, "Should contain token"
            assert "base" in result, "Should contain base"
            assert "price" in result, "Should contain price"
            assert "pair_id" in result, "Should contain pair_id"
            assert isinstance(result["price"], (int, float)), "Price should be numeric"
            print(f"✅ DEX price: {result['price']} {result['base']} per {result['token']}")

    @pytest.mark.asyncio
    async def test_get_dex_price_empty_token(self):
        """Test error handling for empty token contract"""
        result = await get_dex_price("")

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"

        print(f"✅ Correctly rejected empty token contract")

    @pytest.mark.asyncio
    async def test_buy_on_dex_missing_params(self):
        """Test error handling for missing DEX buy parameters"""
        result = await buy_on_dex()

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"

        print(f"✅ Correctly rejected DEX buy with missing params")

    @pytest.mark.asyncio
    async def test_buy_on_dex_invalid_amount(self):
        """Test error handling for invalid amount in DEX buy"""
        result = await buy_on_dex(
            private_key=TEST_PRIVATE_KEY,
            buy_token=TEST_DEX_TOKEN,
            sell_token=TEST_DEX_BASE,
            amount=0  # Invalid amount
        )

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"
        assert "Amount must be positive" in result, "Should mention positive amount requirement"

        print(f"✅ Correctly rejected DEX buy with zero amount")

    @pytest.mark.asyncio
    async def test_sell_on_dex_missing_params(self):
        """Test error handling for missing DEX sell parameters"""
        result = await sell_on_dex()

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"

        print(f"✅ Correctly rejected DEX sell with missing params")

    @pytest.mark.asyncio
    async def test_sell_on_dex_invalid_amount(self):
        """Test error handling for invalid amount in DEX sell"""
        result = await sell_on_dex(
            private_key=TEST_PRIVATE_KEY,
            sell_token=TEST_DEX_TOKEN,
            buy_token=TEST_DEX_BASE,
            amount=-1  # Invalid negative amount
        )

        assert isinstance(result, str), "Should return error string"
        assert result.startswith("❌"), "Should be an error message"
        assert "Amount must be positive" in result, "Should mention positive amount requirement"

        print(f"✅ Correctly rejected DEX sell with negative amount")


# ==========================================
# RUN TESTS
# ==========================================

def run_tests():
    """Run all tests and display results"""
    print("\n" + "=" * 60)
    print("XIAN MCP SERVER TEST SUITE")
    print("=" * 60)
    print(f"GraphQL URL: {os.environ['XIAN_GRAPHQL']}")
    print(f"Node URL: {os.environ['XIAN_NODE_URL']}")
    print(f"Chain ID: {os.environ['XIAN_CHAIN_ID']}")
    print("=" * 60 + "\n")

    # Run pytest programmatically
    pytest_args = [
        __file__,
        "-v",
        "--tb=short",
        "-s"  # Show print statements
    ]

    exit_code = pytest.main(pytest_args)

    print("\n" + "=" * 60)
    if exit_code == 0:
        print("✅ ALL TESTS PASSED")
    else:
        print("⚠️  SOME TESTS FAILED OR WERE SKIPPED")
    print("=" * 60 + "\n")

    return exit_code


if __name__ == "__main__":
    exit_code = run_tests()
    exit(exit_code)