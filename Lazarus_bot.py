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
    return address.lower() in FLAGGED_DEFI_PROTOCOLS

# Handle script termination
def signal_handler(sig, frame):
    print("\U0001F6A8 Script stopped by user.")
    conn.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def send_discord_alert(message):
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
    if not isinstance(address, str):  
        return None
    address = address.strip().replace("'", "").replace('"', "")
    return Web3.to_checksum_address(address) if Web3.is_address(address) else None

def load_addresses(csv_file):
    try:
        df = pd.read_csv(csv_file, header=None, dtype=str)
        return [clean_address(addr) for addr in df[0].tolist() if clean_address(addr)]
    except Exception as e:
        print(f"❌ Error loading CSV: {e}")
        return []

def is_processed(tx_hash):
    cursor.execute("SELECT processed FROM transactions WHERE tx_hash = ?", (tx_hash,))
    return cursor.fetchone() is not None

def mark_processed(tx_hash):
    cursor.execute("INSERT OR IGNORE INTO transactions (tx_hash, processed) VALUES (?, ?)", (tx_hash, True))
    conn.commit()

def get_transactions(address, start_block, end_block):
    payload = {
        "jsonrpc": "2.0", "id": 1, "method": "alchemy_getAssetTransfers",
        "params": [{
            "fromBlock": hex(start_block), "toBlock": hex(end_block),
            "fromAddress": address, "category": ["external", "internal", "erc20"]
        }]
    }
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(ALCHEMY_URL, json=payload, headers=headers)
        return response.json().get("result", {}).get("transfers", []) if response.status_code == 200 else []
    except Exception as e:
        print(f"❌ Error fetching transactions: {e}")
        return []

def track_transactions(addresses):
    latest_block = web3.eth.block_number
    while True:
        current_block = web3.eth.block_number
        if current_block > latest_block:
            for address in addresses:
                transactions = get_transactions(address, latest_block + 1, current_block)
                for tx in transactions:
                    tx_hash, to_address = tx.get("hash"), tx.get("to")
                    if not to_address or is_processed(tx_hash):
                        continue
                    
                    if is_flagged_defi_protocol(to_address):
                        print(f"⚠️ FLAGGED TX: {tx_hash} → {FLAGGED_DEFI_PROTOCOLS[to_address.lower()]}")
                    
                    elif "exchange" in get_address_label(to_address).lower() or "bridge" in get_address_label(to_address).lower():
                        alert_message = f"⚠️ ALERT: Funds moved to {get_address_label(to_address)}\n🔗 TX: {tx_hash}"
                        send_discord_alert(alert_message)
                        print(alert_message)
                    
                    mark_processed(tx_hash)
            latest_block = current_block
        time.sleep(300)

def get_address_label(address):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "alchemy_getTokenMetadata", "params": [address]}
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(ALCHEMY_URL, json=payload, headers=headers)
        return response.json().get("result", {}).get("name", "Unknown") if response.status_code == 200 else "Unknown"
    except Exception as e:
        return "Unknown"

def main():
    print("👁️ The Eyes are watching...\nYou can run, but you can’t hide. The ledger remembers.")
    addresses = load_addresses(CSV_FILE)
    print(f"🔍 Tracking {len(addresses)} valid addresses.")
    if addresses:
        track_transactions(addresses)

if __name__ == "__main__":
    main()
