import asyncio,aiohttp,time,requests,json,sqlite3
import pandas as pd
from web3 import Web3
from colorama import init,Fore,Style

# Initialize colorama for colored console output
init(autoreset=True)

# Alchemy settings
ALCHEMY_URL="https://eth-mainnet.g.alchemy.com/v2/anQCQJL87O5DaXvr4RtMorjxV-7X7U-3"

# Discord webhook
DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/1346791132817915965/6N7yCTc72eMh6-S3M5GrK8GOPpFQTozaa_sOJWLQ5YSnx1O-VPOSUaS5UrkYj2eYg7qN"

# CSV file containing Ethereum addresses (one per line)
CSV_FILE="address.csv"

# Web3 init
web3=Web3(Web3.HTTPProvider(ALCHEMY_URL))

# Thorchain address
THORCHAIN_ADDRESS=Web3.to_checksum_address("0xD37BbE5744D730a1d98d8DC97c42F0Ca46aD7146")

# Interval between checks (10 min = 600s)
CHECK_INTERVAL=600

def initialize_db():
    with sqlite3.connect("transactions.db") as conn:
        c=conn.cursor()
        c.execute("CREATE TABLE IF NOT EXISTS transactions (tx_hash TEXT PRIMARY KEY,processed BOOLEAN)")
        conn.commit()

def clean_address(addr):
    if not isinstance(addr,str):return None
    addr=addr.strip().replace("'","").replace('"',"")
    return Web3.to_checksum_address(addr) if Web3.is_address(addr) else None

def load_addresses_from_csv(csv_file):
    """Read addresses from CSV (one address per line) and validate them."""
    valid=[]
    invalid=[]
    try:
        df=pd.read_csv(csv_file,header=None,dtype=str)
        for raw in df[0].tolist():
            c=clean_address(raw)
            if c:valid.append(c)
            else:invalid.append(raw)
        if invalid:
            print(f"{Fore.YELLOW}⚠ Skipped invalid addresses:{Style.RESET_ALL}")
            for inv in invalid:
                print(f"  - {inv}")
        print(f"{Fore.GREEN}✅ Loaded {len(valid)} valid ETH addresses from {CSV_FILE}.{Style.RESET_ALL}")
        return valid
    except Exception as e:
        print(f"{Fore.RED}❌ Error loading CSV: {e}{Style.RESET_ALL}")
        return []

def is_processed(tx_hash):
    with sqlite3.connect("transactions.db") as conn:
        c=conn.cursor()
        c.execute("SELECT processed FROM transactions WHERE tx_hash=?",(tx_hash,))
        return c.fetchone() is not None

def mark_processed(tx_hash):
    with sqlite3.connect("transactions.db") as conn:
        c=conn.cursor()
        c.execute("INSERT OR IGNORE INTO transactions (tx_hash,processed) VALUES (?,?)",(tx_hash,True))
        conn.commit()

def send_discord_alert(msg):
    payload={"content":msg}
    try:
        r=requests.post(DISCORD_WEBHOOK_URL,json=payload)
        if r.status_code==204:
            print(f"{Fore.GREEN}✅ Discord alert sent!{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}❌ Discord alert failed: {r.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Discord error: {e}{Style.RESET_ALL}")

def is_thorchain(address):
    return address==THORCHAIN_ADDRESS

def get_transactions_single(address,start_block,end_block):
    """Fetch transactions for a single address from Alchemy."""
    payload={
        "jsonrpc":"2.0",
        "id":1,
        "method":"alchemy_getAssetTransfers",
        "params":[{
            "fromBlock":hex(start_block),
            "toBlock":hex(end_block),
            "fromAddress":[address],
            "category":["external","internal","erc20"]
        }]
    }
    headers={"Content-Type":"application/json"}
    try:
        r=requests.post(ALCHEMY_URL,json=payload,headers=headers)
        if r.status_code==200:
            return r.json().get("result",{}).get("transfers",[])
        else:
            print(f"{Fore.RED}❌ Error {r.status_code}: {r.text}{Style.RESET_ALL}")
            return []
    except Exception as e:
        print(f"{Fore.RED}❌ Exception fetching transactions for {address}: {e}{Style.RESET_ALL}")
        return []

def track_single_address(address,start_block,end_block):
    transfers=get_transactions_single(address,start_block,end_block)
    for tx in transfers:
        tx_hash=tx.get("hash")
        to_addr=tx.get("to")
        if not to_addr or is_processed(tx_hash):continue
        to_addr=Web3.to_checksum_address(to_addr)
        from_addr=Web3.to_checksum_address(tx.get("from"))
        if is_thorchain(to_addr):
            print(f"{Fore.YELLOW}⚠ Stopped chain at Thorchain: {to_addr}{Style.RESET_ALL}")
            mark_processed(tx_hash)
            return
        print(f"{Fore.CYAN}🔗 {from_addr} -> {to_addr} | TX: {tx_hash}{Style.RESET_ALL}")
        send_discord_alert(f"🔔 Transaction found:\nTX: {tx_hash}\nFrom: {from_addr}\nTo: {to_addr}")
        mark_processed(tx_hash)

def main_loop(addresses):
    latest_block=web3.eth.block_number
    while True:
        current_block=web3.eth.block_number
        if current_block>latest_block:
            print(f"{Fore.MAGENTA}Scanning blocks {latest_block+1} to {current_block} for {len(addresses)} addresses...{Style.RESET_ALL}")
            for addr in addresses:
                track_single_address(addr,latest_block+1,current_block)
            latest_block=current_block
        time.sleep(CHECK_INTERVAL)

def main():
    print(f"{Fore.BLUE}🚀 Starting single-address transaction monitor...{Style.RESET_ALL}")
    initialize_db()
    addresses=load_addresses_from_csv(CSV_FILE)
    if not addresses:
        print(f"{Fore.RED}❌ No valid addresses. Exiting.{Style.RESET_ALL}")
        return
    print(f"{Fore.BLUE}Tracking {len(addresses)} addresses from {CSV_FILE}...{Style.RESET_ALL}")
    try:
        main_loop(addresses)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}🛑 Stopped by user.{Style.RESET_ALL}")

if __name__=="__main__":
    main()
