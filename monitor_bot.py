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
from datetime import datetime, timedelta

# Initialize colorama for colored terminal output
init(autoreset=True)

# Etherscan API Key
ETHERSCAN_API_KEY = "56A8P3NG3UT21283S8KA6BJ7XPJEVRB9PX"

# Discord Webhook URL
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1346791132817915965/6N7yCTc72eMh6-S3M5GrK8GOPpFQTozaa_sOJWLQ5YSnx1O-VPOSUaS5UrkYj2eYg7qN"

# Ethereum JSON-RPC URL (Using Alchemy)
JSON_RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/anQCQJL87O5DaXvr4RtMorjxV-7X7U-3"

# CSV file path
CSV_FILE = "address.csv"

# Rate limit variables
REQUESTS_PER_SECOND = 5  # Max 5 API calls per second
DAILY_REQUEST_LIMIT = 100000  # Max 100k API calls per day
request_count = 0  # Track total API calls
last_request_time = time.time()  # Track last API call time
daily_reset_time = datetime.now() + timedelta(days=1)  # Reset daily limit at midnight

# Initialize logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Initialize Web3
web3 = Web3(Web3.HTTPProvider(JSON_RPC_URL))

# Initialize SQLite database
conn = sqlite3.connect("transactions.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS transactions (tx_hash TEXT PRIMARY KEY, processed BOOLEAN)")
conn.commit()

# List of flagged addresses (mixers, DeFi protocols, Thorchain)
FLAGGED_ADDRESSES = {
    "0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146": "Thorchain Router V4.1.1",
    "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF": "Tornado Cash",
    # Add more flagged addresses here
}

def is_flagged_address(address):
    """Check if an address is flagged (mixer, DeFi protocol, Thorchain)."""
    return address.lower() in FLAGGED_ADDRESSES

# Signal handler for graceful shutdown
def signal_handler(sig, frame):
    logger.info(f"{Fore.RED}🚨 Script stopped by user. 💀")
    conn.close()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

def send_discord_alert(message):
    """Send an alert to Discord using the webhook."""
    payload = {
        "content": message
    }
    headers = {
        "Content-Type": "application/json"
    }
    try:
        response = requests.post(DISCORD_WEBHOOK_URL, data=json.dumps(payload), headers=headers)
        if response.status_code == 204:
            logger.info(f"{Fore.GREEN}✅ Discord alert sent successfully! 🕷️")
        else:
            logger.error(f"{Fore.RED}❌ Failed to send Discord alert: {response.status_code}")
    except Exception as e:
        logger.error(f"{Fore.RED}❌ Error sending Discord alert: {e}")

def clean_address(address):
    """Sanitize and validate Ethereum addresses from CSV."""
    try:
        if not isinstance(address, str):  
            return None  # Ignore non-string values
        
        address = address.strip().replace("'", "").replace('"', "")  # Remove spaces & quotes
        
        if Web3.is_address(address):  # Validate Ethereum address
            return Web3.to_checksum_address(address)
        else:
            logger.warning(f"{Fore.YELLOW}⚠️ Skipping invalid address: {address}")
            return None  # Ignore invalid addresses
    except Exception as e:
        logger.error(f"{Fore.RED}❌ Error cleaning address {address}: {e}")
        return None

def load_addresses(csv_file):
    """Load and clean addresses from CSV safely."""
    try:
        logger.info(f"{Fore.BLUE}📂 Loading addresses from {csv_file}... 🕸️")
        df = pd.read_csv(csv_file, header=None, dtype=str)  # Read CSV safely
        addresses = [clean_address(addr) for addr in df[0].tolist()]  # Clean addresses
        addresses = [addr for addr in addresses if addr is not None]  # Remove None values
        
        if not addresses:
            logger.error(f"{Fore.RED}❌ No valid addresses found! Please check the CSV file. ☠️")
            return []
        
        logger.info(f"{Fore.GREEN}✅ Successfully loaded {len(addresses)} valid addresses. 🕷️")
        return addresses
    except Exception as e:
        logger.error(f"{Fore.RED}❌ Error loading CSV file: {e}")
        return []

def make_api_request(url, max_retries=3, backoff_factor=2):
    """Make an API request with rate limiting and daily call tracking."""
    global request_count, last_request_time, daily_reset_time

    # Reset daily request count at midnight
    if datetime.now() >= daily_reset_time:
        request_count = 0
        daily_reset_time = datetime.now() + timedelta(days=1)
        logger.info(f"{Fore.BLUE}🔄 Daily API call counter reset. 🕛")

    # Check daily request limit
    if request_count >= DAILY_REQUEST_LIMIT:
        logger.error(f"{Fore.RED}❌ Daily API request limit reached! ☠️")
        return None

    # Check requests per second limit
    elapsed_time = time.time() - last_request_time
    if elapsed_time < 1 / REQUESTS_PER_SECOND:
        time.sleep(1 / REQUESTS_PER_SECOND - elapsed_time)

    # Make the request
    for attempt in range(max_retries):
        try:
            response = requests.get(url)
            request_count += 1
            last_request_time = time.time()
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"{Fore.RED}❌ API request failed: {response.status_code}")
        except Exception as e:
            logger.error(f"{Fore.RED}❌ Error making API request (attempt {attempt + 1}): {e}")
        
        # Exponential backoff
        time.sleep(backoff_factor ** attempt)
    
    logger.error(f"{Fore.RED}❌ Max retries reached for URL: {url}")
    return None

def get_transactions(address, start_block, end_block):
    """Fetch all transactions (ETH and ERC-20) for a given address using Etherscan API."""
    eth_tx_url = f"https://api.etherscan.io/api?module=account&action=txlist&address={address}&startblock={start_block}&endblock={end_block}&sort=asc&apikey={ETHERSCAN_API_KEY}"
    token_tx_url = f"https://api.etherscan.io/api?module=account&action=tokentx&address={address}&startblock={start_block}&endblock={end_block}&sort=asc&apikey={ETHERSCAN_API_KEY}"
    
    # Fetch ETH transactions
    eth_data = make_api_request(eth_tx_url) or {"status": "0", "result": []}
    
    # Fetch ERC-20 token transactions
    token_data = make_api_request(token_tx_url) or {"status": "0", "result": []}
    
    # Combine results
    transactions = eth_data.get("result", []) + token_data.get("result", [])
    return transactions

def is_processed(tx_hash):
    """Check if a transaction has already been processed."""
    cursor.execute("SELECT processed FROM transactions WHERE tx_hash = ?", (tx_hash,))
    return cursor.fetchone() is not None

def mark_processed(tx_hash):
    """Mark a transaction as processed."""
    cursor.execute("INSERT OR IGNORE INTO transactions (tx_hash, processed) VALUES (?, ?)", (tx_hash, True))
    conn.commit()

def track_transaction_chain(from_address, tx_hash, depth=0, max_depth=10):
    """Recursively track a transaction chain until it reaches an exchange, bridge, or flagged address."""
    if depth >= max_depth:
        return None

    try:
        # Fetch transaction details
        tx_url = f"https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash={tx_hash}&apikey={ETHERSCAN_API_KEY}"
        data = make_api_request(tx_url)
        if data and data.get("result"):
            to_address = data["result"].get("to")
            
            if to_address:
                # Check if the to_address is flagged
                if is_flagged_address(to_address):
                    logger.info(f"{Fore.YELLOW}⚠️ Transaction passed through flagged address: {FLAGGED_ADDRESSES[to_address.lower()]}. Chain ignored. 🕷️")
                    return None  # Ignore the chain
                
                # Check if the to_address is an exchange or bridge
                label = get_address_label(to_address)
                if "exchange" in label.lower() or "bridge" in label.lower():
                    return {
                        "from": from_address,
                        "to": to_address,
                        "tx_hash": tx_hash,
                        "label": label,
                        "depth": depth,
                        "next": None
                    }
                else:
                    # Recursively track the next transaction
                    next_tx = track_transaction_chain(to_address, tx_hash, depth + 1, max_depth)
                    if next_tx:
                        return {
                            "from": from_address,
                            "to": to_address,
                            "tx_hash": tx_hash,
                            "label": label,
                            "depth": depth,
                            "next": next_tx
                        }
        return None
    except Exception as e:
        logger.error(f"{Fore.RED}❌ Error tracking transaction chain: {e}")
        return None

def format_transaction_chain(chain):
    """Format the transaction chain for display."""
    result = []
    while chain:
        result.append(f"{chain['from']} → {chain['to']} ({chain['label']}) | Tx Hash: {chain['tx_hash']}")
        chain = chain["next"]
    return "\n".join(result)

def monitor_transactions(addresses):
    """Monitor transactions and send alerts."""
    global request_count
    latest_block_number = get_latest_block_number()
    batch_size = 50  # Number of wallets per batch
    num_batches = (len(addresses) + batch_size - 1) // batch_size  # Calculate number of batches
    
    while True:
        try:
            current_block_number = get_latest_block_number()
            
            if current_block_number > latest_block_number:
                for batch_num in range(num_batches):
                    start_index = batch_num * batch_size
                    end_index = min((batch_num + 1) * batch_size, len(addresses))
                    batch_addresses = addresses[start_index:end_index]
                    
                    logger.info(f"{Fore.BLUE}📊 Monitoring batch {batch_num + 1}/{num_batches}... 🕷️")
                    
                    for address in batch_addresses:
                        transactions = get_transactions(address, latest_block_number + 1, current_block_number)
                        
                        for tx in transactions:
                            tx_hash = tx.get("hash")
                            if is_processed(tx_hash):
                                continue  # Skip already processed transactions
                            
                            from_address = tx.get("from")
                            to_address = tx.get("to")
                            
                            # Check if the transaction is from a monitored address
                            if from_address.lower() == address.lower():
                                # Track the transaction chain
                                chain = track_transaction_chain(from_address, tx_hash)
                                if chain:
                                    message = (
                                        f"⚠️ ALERT: Hacker sent funds to {chain['label']} ({chain['to']})! 🕷️\n"
                                        f"🔗 Transaction Chain:\n{format_transaction_chain(chain)}"
                                    )
                                    logger.info(f"{Fore.YELLOW}{message}")
                                    send_discord_alert(message)
                            
                            # Mark transaction as processed
                            mark_processed(tx_hash)
                
                latest_block_number = current_block_number
            
            # Sleep for 5 minutes before the next cycle
            time.sleep(300)
        except Exception as e:
            logger.error(f"{Fore.RED}❌ Error monitoring transactions: {e}")
            time.sleep(300)

def get_latest_block_number():
    """Get the latest block number."""
    return web3.eth.block_number

# 🔄 Run monitoring loop
def main():
    logger.info(f"{Fore.BLUE}🚀 Starting Ethereum transaction monitor... ☠️ 🕷️ 🕸️")
    addresses = load_addresses(CSV_FILE)
    if not addresses:
        logger.error(f"{Fore.RED}❌ No valid addresses to monitor. Exiting. 💀")
        return

    # Convert addresses to lowercase for comparison
    addresses = [addr.lower() for addr in addresses]
    
    # Start monitoring
    monitor_transactions(addresses)

if __name__ == "__main__":
    main()
