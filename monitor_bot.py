import pandas as pd
from web3 import Web3
import time
import requests
import json
import sqlite3
import signal
import sys

# Alchemy URL (with API key included)
ALCHEMY_URL = "https://eth-mainnet.g.alchemy.com/v2/anQCQJL87O5DaXvr4RtMorjxV-7X7U-3"

# Discord Webhook URL
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1346791132817915965/6N7yCTc72eMh6-S3M5GrK8GOPpFQTozaa_sOJWLQ5YSnx1O-VPOSUaS5UrkYj2eYg7qN"

# CSV file path
CSV_FILE = "address.csv"

# Web3 Initialization
web3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))

# SQLite Database for processed transactions
conn = sqlite3.connect("transactions.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS transactions (tx_hash TEXT PRIMARY KEY, processed BOOLEAN)")
conn.commit()

# List of flagged DeFi protocols (mixers, bridges, privacy tools, etc.)
FLAGGED_DEFI_PROTOCOLS = {
    "0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146": "Thorchain Router V4.1.1",
    "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF": "Tornado Cash",
    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D": "Uniswap Router",
    "0x1111111254fb6c44bAC0beD2854e76F90643097d": "1inch Exchange",
}

def is_flagged_defi_protocol(address):
    """Check if an address is a flagged DeFi protocol."""
    return address.lower() in FLAGGED_DEFI_PROTOCOLS

# Handle script termination
def signal_handler(sig, frame):
    print("🚨 Script stopped by user.")
    conn.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def send_discord_alert(message):
    """Send alerts to Discord webhook."""
    payload = {"content": message}
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, data=json.dumps(payload), headers=headers)
        if response.status_code == 204:
            print("✅ Discord alert sent!")
        else:
            print(f"❌ Failed to send Discord alert: {response.status_code}")
    except Exception as e:
        print(f"❌ Error sending Discord alert: {e}")

def clean_address(address):
    """Sanitize and validate Ethereum addresses."""
    if not isinstance(address, str):  
        return None
    address = address.strip().replace("'", "").replace('"', "")
    return Web3.to_checksum_address(address) if Web3.is_address(address) else None

def load_addresses(csv_file):
    """Load addresses from CSV."""
    try:
        print(f"📂 Loading addresses from {csv_file}...")
        df = pd.read_csv(csv_file, header=None, dtype=str)
        addresses = [clean_address(addr) for addr in df[0].tolist() if clean_address(addr)]
        if not addresses:
            print("❌ No valid addresses found.")
            return []
        print(f"✅ Loaded {len(addresses)} valid addresses.")
        return addresses
    except Exception as e:
        print(f"❌ Error loading CSV file: {e}")
        return []

def is_processed(tx_hash):
    """Check if a transaction was already processed."""
    cursor.execute("SELECT processed FROM transactions WHERE tx_hash = ?", (tx_hash,))
    return cursor.fetchone() is not None

def mark_processed(tx_hash):
    """Mark transaction as processed."""
    cursor.execute("INSERT OR IGNORE INTO transactions (tx_hash, processed) VALUES (?, ?)", (tx_hash, True))
    conn.commit()

def get_transactions(address, start_block, end_block):
    """Fetch transactions using Alchemy API."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "alchemy_getAssetTransfers",
        "params": [{
            "fromBlock": hex(start_block),
            "toBlock": hex(end_block),
            "fromAddress": address,
            "category": ["external", "internal", "erc20", "erc721", "erc1155"]
        }]
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(ALCHEMY_URL, json=payload, headers=headers)
        return response.json().get("result", {}).get("transfers", []) if response.status_code == 200 else []
    except Exception as e:
        print(f"❌ Error fetching transactions: {e}")
        return []

def is_exchange_or_bridge(address):
    """Identify if an address is an exchange or bridge."""
    label = get_address_label(address).lower()
    return "exchange" in label or "bridge" in label

def get_address_label(address):
    """Fetch Alchemy's label for an address."""
    payload = {"jsonrpc": "2.0", "id": 1, "method": "alchemy_getTokenMetadata", "params": [address]}
    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(ALCHEMY_URL, json=payload, headers=headers)
        return response.json().get("result", {}).get("name", "Unknown") if response.status_code == 200 else "Unknown"
    except Exception as e:
        print(f"❌ Error fetching label: {e}")
        return "Unknown"

def track_transaction_chain(from_address, tx_hash, depth=0, max_depth=30, encountered_defi=False):
    """Track transaction chain to detect fund movement."""
    if depth >= max_depth:
        return None

    try:
        tx = web3.eth.get_transaction(tx_hash)
        to_address = tx.get("to")

        if not to_address:
            return None

        if is_flagged_defi_protocol(to_address):
            print(f"🔹 Wallet {from_address} interacted with {FLAGGED_DEFI_PROTOCOLS[to_address.lower()]} at depth {depth}.")
            return {"from": from_address, "to": to_address, "tx_hash": tx_hash, "depth": depth, "next": None}

        if is_exchange_or_bridge(to_address):
            if encountered_defi:
                print("🔹 No alert: Transaction reached exchange but passed through a DeFi protocol.")
                return None
            return {"from": from_address, "to": to_address, "tx_hash": tx_hash, "depth": depth, "next": None}

        next_tx = track_transaction_chain(to_address, tx_hash, depth + 1, max_depth, encountered_defi)
        if next_tx:
            return {"from": from_address, "to": to_address, "tx_hash": tx_hash, "depth": depth, "next": next_tx}

    except Exception as e:
        print(f"❌ Error tracking transaction: {e}")
    
    return None

def monitor_transactions(addresses):
    """Monitor transactions and send alerts when needed."""
    latest_block_number = web3.eth.block_number

    while True:
        current_block_number = web3.eth.block_number
        if current_block_number > latest_block_number:
            for address in addresses:
                transactions = get_transactions(address, latest_block_number + 1, current_block_number)

                for tx in transactions:
                    tx_hash = tx.get("hash")
                    if is_processed(tx_hash):
                        continue
                    
                    chain = track_transaction_chain(tx.get("from"), tx_hash)
                    if chain and not is_flagged_defi_protocol(chain["to"]):
                        send_discord_alert(f"⚠️ ALERT: Fund movement detected!\n🔗 {chain}")
                    
                    mark_processed(tx_hash)

            latest_block_number = current_block_number
        time.sleep(300)

def main():
    print("🚀 Starting Ethereum transaction monitor...")
    addresses = load_addresses(CSV_FILE)
    if addresses:
        monitor_transactions(addresses)

if __name__ == "__main__":
    main()

