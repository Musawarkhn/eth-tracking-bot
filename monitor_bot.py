import pandas as pd
from web3 import Web3
import time
import requests
import json
import logging
from colorama import Fore, Style, init
import signal
import sys
import sqlite3

# Initialize colorama for colored terminal output
init(autoreset=True)

# Alchemy API Key and URL
ALCHEMY_API_KEY = "anQCQJL87O5DaXvr4RtMorjxV-7X7U-3"
ALCHEMY_URL = f"https://eth-mainnet.g.alchemy.com/v2/{ALCHEMY_API_KEY}"

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
    "0xd37bbe5744d730a1d98d8dc97c42f0ca46ad7146": "Thorchain Router V4.1.1",
    "0x910cbd523d972eb0a6f4cae4618ad62622b39dbf": "Tornado Cash",
    "0x7a250d5630b4cf539739df2c5dacb4c659f2488d": "Uniswap Router",
    "0x1111111254fb6c44bac0bed2854e76f90643097d": "1inch Exchange",
}

def is_flagged_defi_protocol(address):
    """Check if an address is a flagged DeFi protocol."""
    return address and address.lower() in FLAGGED_DEFI_PROTOCOLS

# Logger Setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(_name_)

# Handle script termination
def signal_handler(sig, frame):
    logger.info(f"{Fore.RED}🚨 Script stopped by user.")
    conn.close()  # Ensure database closes properly
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def send_discord_alert(message):
    """Send alerts to Discord webhook."""
    payload = {"content": message}
    headers = {"Content-Type": "application/json"}
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, data=json.dumps(payload), headers=headers)
        if response.status_code == 204:
            logger.info(f"{Fore.GREEN}✅ Discord alert sent!")
        else:
            logger.error(f"{Fore.RED}❌ Failed to send Discord alert: {response.status_code}")
    except Exception as e:
        logger.error(f"{Fore.RED}❌ Error sending Discord alert: {e}")

def clean_address(address):
    """Sanitize and validate Ethereum addresses."""
    if not isinstance(address, str):  
        return None
    address = address.strip().replace("'", "").replace('"', "")
    return Web3.to_checksum_address(address) if Web3.is_address(address) else None

def load_addresses(csv_file):
    """Load addresses from CSV."""
    try:
        logger.info(f"{Fore.BLUE}📂 Loading addresses from {csv_file}...")
        df = pd.read_csv(csv_file, header=None, dtype=str)
        addresses = [clean_address(addr) for addr in df[0].tolist() if clean_address(addr)]
        if not addresses:
            logger.error(f"{Fore.RED}❌ No valid addresses found.")
            return []
        logger.info(f"{Fore.GREEN}✅ Loaded {len(addresses)} valid addresses.")
        return addresses
    except Exception as e:
        logger.error(f"{Fore.RED}❌ Error loading CSV file: {e}")
        return []

def is_processed(tx_hash):
    """Check if a transaction was already processed."""
    if not tx_hash:
        return True
    cursor.execute("SELECT processed FROM transactions WHERE tx_hash = ?", (tx_hash,))
    return cursor.fetchone() is not None

def mark_processed(tx_hash):
    """Mark transaction as processed."""
    if tx_hash:
        cursor.execute("INSERT OR IGNORE INTO transactions (tx_hash, processed) VALUES (?, ?)", (tx_hash, True))
        conn.commit()

def get_transactions(address, start_block, end_block):
    """Fetch transactions using Alchemy API."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "alchemy_getAssetTransfers",
        "params": [{
            "fromBlock": str(hex(start_block)),
            "toBlock": str(hex(end_block)),
            "fromAddress": address,
            "category": ["external", "internal", "erc20", "erc721", "erc1155"]
        }]
    }
    headers = {"Content-Type": "application/json"}
    
    try:
        response = requests.post(ALCHEMY_URL, json=payload, headers=headers)
        if response.status_code == 200:
            return response.json().get("result", {}).get("transfers", [])
    except Exception as e:
        logger.error(f"{Fore.RED}❌ Error fetching transactions: {e}")
    return []

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
                    tx_to = tx.get("to")

                    if is_processed(tx_hash) or not tx_to:
                        continue

                    if is_flagged_defi_protocol(tx_to):
                        send_discord_alert(f"⚠️ ALERT: Address {tx_to} is flagged as {FLAGGED_DEFI_PROTOCOLS.get(tx_to.lower(), 'Unknown')}")

                    mark_processed(tx_hash)

            latest_block_number = current_block_number
        time.sleep(300)

def main():
    logger.info(f"{Fore.BLUE}🚀 Starting Ethereum transaction monitor...")
    addresses = load_addresses(CSV_FILE)
    if addresses:
        monitor_transactions(addresses)

if _name_ == "_main_":
    main()
