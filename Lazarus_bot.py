import time
import requests
import json
import sqlite3
import pandas as pd
from web3 import Web3
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

# Alchemy URL and API Key
ALCHEMY_URL = "https://eth-mainnet.g.alchemy.com/v2/08Z_zvM9m-WA-s5xwrp5aQOcmrnnG_ML"
ALCHEMY_API_KEY = "08Z_zvM9m-WA-s5xwrp5aQOcmrnnG_ML"

# Discord Webhook URL
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1346791132817915965/6N7yCTc72eMh6-S3M5GrK8GOPpFQTozaa_sOJWLQ5YSnx1O-VPOSUaS5UrkYj2eYg7qN"

# CSV file path
CSV_FILE = "address.csv"

# Web3 Initialization
web3 = Web3(Web3.HTTPProvider(ALCHEMY_URL))

# Thorchain address (stop tracking if this is involved)
THORCHAIN_ADDRESS = Web3.to_checksum_address("0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146")

# Check interval in seconds (10 minutes = 600 seconds)
CHECK_INTERVAL = 600

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
                print(f"{Fore.GREEN}✅ Discord alert sent!{Style.RESET_ALL}")
                return
            else:
                print(f"{Fore.RED}❌ Failed to send Discord alert (Attempt {attempt + 1}): {response.status_code}{Style.RESET_ALL}")
                time.sleep(2 ** attempt)  # Exponential backoff
        except Exception as e:
            print(f"{Fore.RED}❌ Error sending Discord alert: {e}{Style.RESET_ALL}")
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
        addresses = []
        invalid = []
        for raw in df[0].tolist():
            cleaned = clean_address(raw)
            if cleaned:
                addresses.append(cleaned)
            else:
                invalid.append(raw)
        if invalid:
            print(f"{Fore.YELLOW}⚠ Skipped invalid addresses:{Style.RESET_ALL}")
            for inv in invalid:
                print(f"  - {inv}")
        print(f"{Fore.GREEN}✅ Loaded {len(addresses)} valid addresses from {csv_file}.{Style.RESET_ALL}")
        return addresses
    except Exception as e:
        print(f"{Fore.RED}❌ Error loading CSV: {e}{Style.RESET_ALL}")
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

def get_transactions(address, start_block, end_block, retries=3):
    """Fetch transactions for a single address using Alchemy API with retry logic."""
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "alchemy_getAssetTransfers",
        "params": [{
            "fromBlock": hex(start_block),
            "toBlock": hex(end_block),
            "fromAddress": address,  # Single address
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
                # Send Discord alert for API errors
                error_message = f"❌ Alchemy API Error (Attempt {attempt + 1}): {response.status_code}\n"
                if response.status_code == 429:
                    error_message += "Rate limit exceeded. Please check your Alchemy plan."
                elif response.status_code == 403:
                    error_message += "Unauthorized. Your Alchemy API key may be expired or invalid."
                else:
                    error_message += f"Response: {response.text}"
                send_discord_alert(error_message)
                print(f"{Fore.RED}{error_message}{Style.RESET_ALL}")
                time.sleep(2 ** attempt)  # Exponential backoff
        except Exception as e:
            error_message = f"❌ Error fetching transactions for {address}: {e}"
            send_discord_alert(error_message)
            print(f"{Fore.RED}{error_message}{Style.RESET_ALL}")
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
        print(f"{Fore.RED}❌ Error fetching label for {address}: {e}{Style.RESET_ALL}")
        return "Unknown"

def is_exchange_or_bridge(address):
    """Check if an address is an exchange or bridge using Alchemy's label."""
    label = get_address_label(address).lower()
    return "exchange" in label or "bridge" in label

def track_transaction_chain(from_address, to_address, tx_hash, depth=0, max_depth=30, chain=None, visited=None):
    """Recursively track a transaction chain."""
    if chain is None:
        chain = []
    if visited is None:
        visited = set()
    if depth >= max_depth or from_address in visited or to_address in visited:
        return chain  # Stop if max depth is reached or addresses are already visited

    visited.add(from_address)
    visited.add(to_address)

    from_label = get_address_label(from_address)
    to_label = get_address_label(to_address)

    chain.append({
        "from": from_address,
        "from_label": from_label,
        "to": to_address,
        "to_label": to_label,
        "tx_hash": tx_hash,
        "depth": depth
    })

    if is_thorchain(to_address):
        # Print Thorchain alert to terminal
        print(f"{Fore.YELLOW}⚠️ Transaction chain stopped: Thorchain detected at {to_address}{Style.RESET_ALL}")
        # Send Thorchain alert to Discord
        send_discord_alert(f"⚠️ Thorchain Detected!\n"
                           f"Transaction Chain Stopped at: {to_address}\n"
                           f"Transaction Hash: {tx_hash}")
        return chain  # Stop tracking this chain

    if is_exchange_or_bridge(to_address):
        print(f"{Fore.YELLOW}⚠️ Transaction chain ended at {to_address} ({to_label}){Style.RESET_ALL}")
        return chain

    transactions = get_transactions(to_address, web3.eth.block_number - 100, web3.eth.block_number)
    for tx in transactions:
        next_tx_hash, next_to_address = tx.get("hash"), tx.get("to")
        if not next_to_address or is_processed(next_tx_hash):
            continue
        next_to_address = Web3.to_checksum_address(next_to_address)
        next_from_address = Web3.to_checksum_address(tx.get("from"))
        return track_transaction_chain(to_address, next_to_address, next_tx_hash, depth + 1, max_depth, chain, visited)

    return chain

def save_transaction_chain(chain):
    """Save the transaction chain to a file."""
    with open("transaction_chains.csv", "a") as f:
        for link in chain:
            f.write(f"{link['from']},{link['from_label']},{link['to']},{link['to_label']},{link['tx_hash']},{link['depth']}\n")

def track_transactions(addresses):
    """Monitor transactions and track fund movements."""
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
                    to_address = Web3.to_checksum_address(to_address)
                    from_address = Web3.to_checksum_address(tx.get("from"))
                    chain = track_transaction_chain(from_address, to_address, tx_hash)
                    if chain:
                        print(f"{Fore.CYAN}🔗 Full Transaction Chain:\n{json.dumps(chain, indent=2)}{Style.RESET_ALL}")
                        send_discord_alert(f"🔔 Transaction Chain Detected:\n{json.dumps(chain, indent=2)}")
                        save_transaction_chain(chain)
                    mark_processed(tx_hash)
            latest_block = current_block
        time.sleep(CHECK_INTERVAL)

def main():
    print(f"{Fore.GREEN}🚀 Starting Ethereum transaction monitor...{Style.RESET_ALL}")
    addresses = load_addresses(CSV_FILE)
    if addresses:
        print(f"{Fore.GREEN}✅ Tracking {len(addresses)} valid wallets.{Style.RESET_ALL}")
        try:
            track_transactions(addresses)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}🛑 Stopped by user.{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}❌ No valid wallets to track.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
