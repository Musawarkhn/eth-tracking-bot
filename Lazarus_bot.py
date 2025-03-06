import asyncio
import aiohttp
from web3 import Web3
import time
import requests
import json
import sqlite3

ALCHEMY_URL = "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY_HERE"
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_ID/YOUR_WEBHOOK_TOKEN"
HACKER_API_URL = "https://hackscan.hackbounty.io/public/hack-address.json"

web3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))

CHECK_INTERVAL = 600  # how often we re-check
THORCHAIN_ADDRESS = Web3.to_checksum_address("0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146")

def initialize_db():
    with sqlite3.connect("transactions.db") as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                tx_hash TEXT PRIMARY KEY,
                processed BOOLEAN
            )
        """)
        conn.commit()

def clean_address(address):
    if not isinstance(address, str):
        return None
    address = address.strip().replace("'", "").replace('"', "")
    return Web3.to_checksum_address(address) if Web3.is_address(address) else None

def load_addresses_from_api(api_url):
    valid_addresses = []
    try:
        resp = requests.get(api_url)
        if resp.status_code != 200:
            print(f"❌ Error fetching addresses: {resp.status_code}")
            return []
        data = resp.json()
        # Example structure: { "0221": { "eth": [ "0x...", ...], "bsc": [...] }, ... }
        for date_key, chain_data in data.items():
            eth_list = chain_data.get("eth", [])
            for addr in eth_list:
                c = clean_address(addr)
                if c:
                    valid_addresses.append(c)
                else:
                    print(f"⚠️ Invalid address skipped: {addr}")
        print(f"✅ Loaded {len(valid_addresses)} valid ETH addresses from API.")
        return valid_addresses
    except Exception as e:
        print(f"❌ Error: {e}")
        return []

def is_processed(tx_hash):
    with sqlite3.connect("transactions.db") as conn:
        c = conn.cursor()
        c.execute("SELECT processed FROM transactions WHERE tx_hash = ?", (tx_hash,))
        return c.fetchone() is not None

def mark_processed(tx_hash):
    with sqlite3.connect("transactions.db") as conn:
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO transactions (tx_hash, processed) VALUES (?, ?)", (tx_hash, True))
        conn.commit()

def send_discord_alert(message):
    payload = {"content": message}
    try:
        r = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        if r.status_code == 204:
            print("✅ Discord alert sent!")
        else:
            print(f"❌ Discord alert failed: {r.status_code}")
    except Exception as e:
        print(f"❌ Discord error: {e}")

def is_thorchain(address):
    return address == THORCHAIN_ADDRESS

def get_transactions_single(address, start_block, end_block):
    """Fetch transactions for a single address using Alchemy."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "alchemy_getAssetTransfers",
        "params": [{
            "fromBlock": hex(start_block),
            "toBlock": hex(end_block),
            "fromAddress": [address],  # single address in a list
            "category": ["external", "internal", "erc20"]
        }]
    }
    headers = {"Content-Type": "application/json"}
    try:
        r = requests.post(ALCHEMY_URL, json=payload, headers=headers)
        if r.status_code == 200:
            return r.json().get("result", {}).get("transfers", [])
        else:
            print(f"❌ Error {r.status_code}: {r.text}")
            return []
    except Exception as e:
        print(f"❌ Exception fetching transactions for {address}: {e}")
        return []

def track_single_address(address, start_block, end_block):
    """Track one address for new transactions."""
    transfers = get_transactions_single(address, start_block, end_block)
    for tx in transfers:
        tx_hash = tx.get("hash")
        to_addr = tx.get("to")
        if not to_addr or is_processed(tx_hash):
            continue
        to_addr = Web3.to_checksum_address(to_addr)
        from_addr = Web3.to_checksum_address(tx.get("from"))

        # If you want to stop on Thorchain or do labeling, you can add that logic here
        if is_thorchain(to_addr):
            print(f"⚠️ Stopped chain at Thorchain: {to_addr}")
            mark_processed(tx_hash)
            return

        # Do whatever chain tracking logic you want...
        # For now, we just print and alert
        print(f"🔗 {from_addr} -> {to_addr} | TX: {tx_hash}")
        send_discord_alert(f"🔔 Transaction found: {tx_hash}\nFrom: {from_addr}\nTo: {to_addr}")
        mark_processed(tx_hash)

def main_loop(addresses):
    latest_block = web3.eth.block_number
    while True:
        current_block = web3.eth.block_number
        if current_block > latest_block:
            # For each new block, check all addresses one by one
            for addr in addresses:
                track_single_address(addr, latest_block + 1, current_block)
            latest_block = current_block
        time.sleep(CHECK_INTERVAL)

def main():
    print("🚀 Starting single-address transaction monitor...")
    initialize_db()
    addresses = load_addresses_from_api(HACKER_API_URL)
    if not addresses:
        print("❌ No valid addresses. Exiting.")
        return
    print(f"Tracking {len(addresses)} addresses from the API...")
    try:
        main_loop(addresses)
    except KeyboardInterrupt:
        print("\n🛑 Stopped by user.")

if __name__ == "__main__":
    main()
