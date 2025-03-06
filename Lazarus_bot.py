import pandas as pd
from web3 import Web3
import time
import requests
import json
import sqlite3
import signal
import sys

# Alchemy URL and API Key
ALCHEMY_URL = "https://eth-mainnet.g.alchemy.com/v2/anQCQJL87O5DaXvr4RtMorjxV-7X7U-3"
ALCHEMY_API_KEY = "anQCQJL87O5DaXvr4RtMorjxV-7X7U-3"

# Discord Webhook URL
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1346791132817915965/6N7yCTc72eMh6-S3M5GrK8GOPpFQTozaa_sOJWLQ5YSnx1O-VPOSUaS5UrkYj2eYg7qN"

# CSV file path
CSV_FILE = "address.csv"

# Web3 Initialization
web3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))

# Thorchain address (stop tracking if this is involved)
THORCHAIN_ADDRESS = Web3.to_checksum_address("0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146")

def is_thorchain(address):
    """Check if an address is Thorchain."""
    return Web3.to_checksum_address(address) == THORCHAIN_ADDRESS

def send_discord_alert(message, retries=3):
    """Send alerts to Discord webhook with retry logic."""
    payload = {"content": message}
    headers = {"Content-Type": "application/json"}
    for attempt in range(retries):
        try:
            response = requests.post(DISCORD_WEBHOOK_URL, data=json.dumps(payload), headers=headers)
            if response.status_code == 204:
                print("✅ Discord alert sent!")
                return
            else:
                print(f"❌ Failed to send Discord alert (Attempt {attempt + 1}): {response.status_code}")
                time.sleep(2 ** attempt)  # Exponential backoff
        except Exception as e:
            print(f"❌ Error sending Discord alert: {e}")
            time.sleep(2 ** attempt)  # Exponential backoff

def clean_address(address):
    """Sanitize and validate Ethereum addresses."""
    if not isinstance(address, str):  
        return None
    address = address.strip().replace("'", "").replace('"', "")
    return Web3.to_checksum_address(address) if Web3.is_address(address) else None

def load_addresses(csv_file):
    """Load addresses from CSV."""
    try:
        df = pd.read_csv(csv_file, header=None, dtype=str)
        return [clean_address(addr) for addr in df[0].tolist() if clean_address(addr)]
    except Exception as e:
        print(f"❌ Error loading CSV: {e}")
        return []

def is_processed(tx_hash):
    """Check if a transaction was already processed."""
    with sqlite3.connect("transactions.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT processed FROM transactions WHERE tx_hash = ?", (tx_hash,))
        return cursor.fetchone() is not None

def mark_processed(tx_hash):
    """Mark transaction as processed."""
    with sqlite3.connect("transactions.db") as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT OR IGNORE INTO transactions (tx_hash, processed) VALUES (?, ?)", (tx_hash, True))
        conn.commit()

def get_transactions(addresses, start_block, end_block, retries=3):
    """Fetch transactions using Alchemy API with retry logic."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "alchemy_getAssetTransfers",
        "params": [{
            "fromBlock": hex(start_block),
            "toBlock": hex(end_block),
            "fromAddress": addresses,
            "category": ["external", "internal", "erc20"]
        }]
    }
    headers = {"Content-Type": "application/json"}
    for attempt in range(retries):
        try:
            response = requests.post(ALCHEMY_URL, json=payload, headers=headers)
            if response.status_code == 200:
                return response.json().get("result", {}).get("transfers", [])
            else:
                print(f"❌ API Error (Attempt {attempt + 1}): {response.status_code}")
                time.sleep(2 ** attempt)  # Exponential backoff
        except Exception as e:
            print(f"❌ Error fetching transactions: {e}")
            time.sleep(2 ** attempt)  # Exponential backoff
    return []  # Return empty list if all retries fail

def get_address_label(address):
    """Fetch Alchemy's label for an address."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "alchemy_getTokenMetadata",
        "params": [address]
    }
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(ALCHEMY_URL, json=payload, headers=headers)
        if response.status_code == 200:
            result = response.json().get("result", {})
            return result.get("name", "Unknown")
        else:
            return "Unknown"
    except Exception as e:
        print(f"❌ Error fetching label for {address}: {e}")
        return "Unknown"

def is_exchange_or_bridge(address):
    """Check if an address is an exchange or bridge using Alchemy's label."""
    label = get_address_label(address).lower()
    return "exchange" in label or "bridge" in label

def track_external_wallet(wallet_address, depth=0, max_depth=30, chain=None, visited=None):
    """Recursively track transactions from an external wallet."""
    if chain is None:
        chain = []
    if visited is None:
        visited = set()
    if depth >= max_depth or wallet_address in visited:
        return chain  # Stop if max depth is reached or wallet is already visited

    visited.add(wallet_address)  # Mark wallet as visited

    try:
        # Fetch transactions for the external wallet
        transactions = get_transactions([wallet_address], web3.eth.block_number - 100, web3.eth.block_number)
        for tx in transactions:
            tx_hash, to_address = tx.get("hash"), tx.get("to")
            if not to_address or is_processed(tx_hash):
                continue

            to_address = Web3.to_checksum_address(to_address)
            from_address = Web3.to_checksum_address(tx.get("from"))

            # Fetch labels for addresses
            from_label = get_address_label(from_address)
            to_label = get_address_label(to_address)

            # Append transaction to chain
            chain.append({
                "from": from_address,
                "from_label": from_label,
                "to": to_address,
                "to_label": to_label,
                "tx_hash": tx_hash,
                "depth": depth
            })

            # Check if Thorchain is involved
            if is_thorchain(to_address):
                print(f"⚠️ Transaction chain stopped: Thorchain detected at {to_address}")
                return None  # Stop tracking this chain

            # Check if the recipient is an exchange or bridge
            if is_exchange_or_bridge(to_address):
                print(f"⚠️ Transaction chain ended at {to_address} ({to_label})")
                return chain

            # Recursively track the next wallet in the chain
            return track_external_wallet(to_address, depth + 1, max_depth, chain, visited)

    except Exception as e:
        print(f"❌ Error tracking external wallet: {e}")

    return chain

def track_transactions(addresses):
    """Monitor transactions and track fund movements."""
    latest_block = web3.eth.block_number
    batch_size = 100  # Batch addresses to reduce CU usage
    csv_addresses = set(addresses)  # Convert to set for faster lookup

    while True:
        current_block = web3.eth.block_number
        if current_block > latest_block:
            for i in range(0, len(addresses), batch_size):
                batch_addresses = addresses[i:i + batch_size]
                transactions = get_transactions(batch_addresses, latest_block + 1, current_block)
                for tx in transactions:
                    tx_hash, to_address = tx.get("hash"), tx.get("to")
                    if not to_address or is_processed(tx_hash):
                        continue

                    to_address = Web3.to_checksum_address(to_address)
                    from_address = Web3.to_checksum_address(tx.get("from"))

                    # Check if the recipient is outside the CSV file
                    if not is_address_in_csv(to_address, csv_addresses):
                        print(f"🔍 External Wallet Detected: {to_address} received tokens from {from_address}")
                        # Track the external wallet's transactions
                        chain = track_external_wallet(to_address)
                        if chain:
                            print(f"🔗 Transaction Chain:\n{json.dumps(chain, indent=2)}")
                            send_discord_alert(f"🔔 Transaction Chain Detected:\n{json.dumps(chain, indent=2)}")
                            save_transaction_chain(chain)

                    mark_processed(tx_hash)
            latest_block = current_block
        time.sleep(600)  # Updated interval to 10 minutes

def save_transaction_chain(chain):
    """Save the transaction chain to a file."""
    with open("transaction_chains.csv", "a") as f:
        for link in chain:
            f.write(f"{link['from']},{link['from_label']},{link['to']},{link['to_label']},{link['tx_hash']},{link['depth']}\n")

def is_address_in_csv(address, csv_addresses):
    """Check if an address is in the CSV file."""
    return Web3.to_checksum_address(address) in csv_addresses

def main():
    print("🚀 Starting Ethereum transaction monitor...")
    addresses = load_addresses(CSV_FILE)
    if addresses:
        track_transactions(addresses)

if __name__ == "__main__":
    main()
