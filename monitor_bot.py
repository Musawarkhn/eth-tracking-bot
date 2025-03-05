import pandas as pd
from web3 import Web3
import time
import requests
import json
import logging
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)

# 🚀 Ethereum JSON-RPC URL (Using Alchemy)
JSON_RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/anQCQJL87O5DaXvr4RtMorjxV-7X7U-3"

# 📂 CSV file path
csv_file = "address.csv"

# Discord Webhook URL
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1346791132817915965/6N7yCTc72eMh6-S3M5GrK8GOPpFQTozaa_sOJWLQ5YSnx1O-VPOSUaS5UrkYj2eYg7qN"

# ERC-20 Transfer Event Signature
ERC20_TRANSFER_TOPIC = Web3.keccak(text="Transfer(address,address,uint256)").hex()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Initialize Web3
web3 = Web3(Web3.HTTPProvider(JSON_RPC_URL))

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
            logger.info(f"{Fore.GREEN}✅ Discord alert sent successfully!")
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
        logger.info(f"{Fore.BLUE}📂 Loading addresses from {csv_file}...")
        df = pd.read_csv(csv_file, header=None, dtype=str)  # Read CSV safely
        addresses = [clean_address(addr) for addr in df[0].tolist()]  # Clean addresses
        addresses = [addr for addr in addresses if addr is not None]  # Remove None values
        
        if not addresses:
            logger.error(f"{Fore.RED}❌ No valid addresses found! Please check the CSV file.")
            return []
        
        logger.info(f"{Fore.GREEN}✅ Successfully loaded {len(addresses)} valid addresses.")
        return addresses
    except Exception as e:
        logger.error(f"{Fore.RED}❌ Error loading CSV file: {e}")
        return []

# 🔍 Major Exchanges and Bridges Hot Wallets
EXCHANGE_ADDRESSES = {
    "Binance": "0x3f5CE5FBFe3E9af3971dD833D26bA9eEeC09D9d3",
    "Coinbase": "0x503828976D22510aad0201ac7EC88293211D23Da",
    "Kraken": "0x9B86d1c5b9F35d6B4c79A68B3FCFBa0f24E62D29",
    "KuCoin": "0xEB2629a2734e272Bcc07BDA959863f316F4bD4Cf",
    "OKX": "0x2B5634C42055806a59e9107ED44D43c426E58258",
    "Huobi": "0x5c985E89D7A0F5aEbF02E7D03cCb861a4290f2C2",
    "Bybit": "0x324c5c27e7b0c5987dbbdbbe5e9e9fa11b10a711",
    "Gate.io": "0xD4B9a6A673fbC60F57E4D1B765D9B144897B2e99",
    "Bitfinex": "0x876eabF441B2EE5B5b0554FD502a8e0600950cFa",
    "MEXC": "0x47a91457a3a1f700097199fd63c039c4784384ab",
    "Crypto.com": "0x59A5208B32e627891C389EBafc644145224006E8",
    "Bitstamp": "0x4BFEEbe9D8DB97813bdCcB6379E20EfaA772A16b",
    "Upbit": "0x653477c392c16b0765603074f15760c43b4a70d4",
    "Bithumb": "0x4D0F77DaD7aEdDBe4b1fd202F0F8126F0DB4Bff3",
    "OKCoin": "0x35F3AF0b10eC2eD4E251162F4D4B3896F37cC659",
    "Bitget": "0xc21D6473F84aCB07A5cB84c1D2216dc63c99aB49",
    "Gemini": "0xB527a981e1D415af696936B3174F2d7AC8d1153b",
    
    # 🌉 Bridges
    "Multichain": "0xD2D1F29A95A1aE3F1B4C42998B3019F0cF3a3D46",
    "Synapse": "0x2796317b0fF8538F253012862c06787Adfb8cEb6",
    "Stargate": "0x8731d54E9D02c286767d56ac03e8037C07e01e98",
    "Hop Protocol": "0x8f5b09d19F684B7cDA50DeF94b8fDf19c315ABa1",
    "Across Protocol": "0xE4F1A71cE87eFD6EAcA5fb1f406B9C094c99eD72",
    "Celer Bridge": "0x5427a3Aca4b205FF8E9F092F8e576Ce066C242c5",
}

# 🚫 DeFi Mixers and Laundering Protocols
DEFI_MIXERS = {
    "Tornado Cash": "0x910Cbd523D972eb0a6f4cAe4618aD62622b39DbF",
    "Thorchain Router": "0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146",
    # Add more DeFi mixers or laundering protocols here
}

EXCHANGE_NAMES = {Web3.to_checksum_address(v): k for k, v in EXCHANGE_ADDRESSES.items()}
DEFI_MIXER_ADDRESSES = {Web3.to_checksum_address(v) for v in DEFI_MIXERS.values()}

def is_defi_mixer(address):
    """Check if an address is a known DeFi mixer or laundering protocol."""
    return address in DEFI_MIXER_ADDRESSES

def get_latest_block_number():
    """Get the latest block number."""
    return web3.eth.block_number

def get_transactions_in_block(block_number):
    """Get all transactions in a specific block."""
    block = web3.eth.get_block(block_number, full_transactions=True)
    return block.transactions

def track_transaction_chain(from_address, tx_hash, depth=0, max_depth=30):
    """Recursively track a transaction chain until it reaches an exchange or bridge."""
    if depth >= max_depth:
        return None

    try:
        receipt = web3.eth.get_transaction_receipt(tx_hash)
        for log in receipt["logs"]:
            if log["topics"][0].hex() == ERC20_TRANSFER_TOPIC:
                to_address = Web3.to_checksum_address(log["topics"][2][-40:])
                
                # Skip if the to_address is a DeFi mixer or laundering protocol
                if is_defi_mixer(to_address):
                    logger.info(f"{Fore.YELLOW}⚠️ Skipping DeFi mixer/laundering protocol: {to_address}")
                    return None
                
                if to_address in EXCHANGE_NAMES:
                    return to_address
                else:
                    # Check if the to_address sends any transactions
                    next_tx = track_transaction_chain(to_address, tx_hash, depth + 1, max_depth)
                    if next_tx:
                        return next_tx
        return None
    except Exception as e:
        logger.error(f"{Fore.RED}❌ Error tracking transaction chain: {e}")
        return None

def monitor_transactions(addresses):
    """Monitor transactions and send alerts."""
    latest_block_number = get_latest_block_number()
    
    while True:
        try:
            current_block_number = get_latest_block_number()
            
            if current_block_number > latest_block_number:
                for block_number in range(latest_block_number + 1, current_block_number + 1):
                    transactions = get_transactions_in_block(block_number)
                    
                    for tx in transactions:
                        from_address = tx["from"]
                        to_address = tx.get("to")
                        
                        # Check if the transaction is from a monitored address
                        if from_address.lower() in addresses:
                            # Skip if the to_address is a DeFi mixer or laundering protocol
                            if is_defi_mixer(to_address):
                                logger.info(f"{Fore.YELLOW}⚠️ Skipping DeFi mixer/laundering protocol: {to_address}")
                                continue
                            
                            # Check if the recipient is a known exchange/bridge
                            if to_address in EXCHANGE_NAMES:
                                message = f"⚠️ ALERT: Hacker sent ETH to {EXCHANGE_NAMES[to_address]}!\n🔗 Transaction Hash: {tx['hash'].hex()}"
                                logger.info(f"{Fore.YELLOW}{message}")
                                send_discord_alert(message)
                            else:
                                # Track the transaction chain
                                final_destination = track_transaction_chain(from_address, tx["hash"])
                                if final_destination and final_destination in EXCHANGE_NAMES:
                                    message = f"⚠️ ALERT: Hacker sent tokens to {EXCHANGE_NAMES[final_destination]}!\n🔗 Transaction Hash: {tx['hash'].hex()}"
                                    logger.info(f"{Fore.YELLOW}{message}")
                                    send_discord_alert(message)
                
                latest_block_number = current_block_number
            
            time.sleep(10)  # Poll every 10 seconds
        except Exception as e:
            logger.error(f"{Fore.RED}❌ Error monitoring transactions: {e}")
            time.sleep(10)

# 🔄 Run monitoring loop
def main():
    logger.info(f"{Fore.BLUE}🚀 Starting Ethereum transaction monitor...")
    addresses = load_addresses(csv_file)
    if not addresses:
        logger.error(f"{Fore.RED}❌ No valid addresses to monitor. Exiting.")
        return

    # Convert addresses to lowercase for comparison
    addresses = [addr.lower() for addr in addresses]
    
    # Start monitoring
    monitor_transactions(addresses)

if __name__ == "__main__":
    main()
