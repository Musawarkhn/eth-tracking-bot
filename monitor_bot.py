import json
import time
import requests
import pandas as pd
from web3 import Web3

# Ethereum RPC URL using your Alchemy API key
ETH_RPC_URL = "https://eth-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_API_KEY"

# Load hacker addresses from CSV file
HACKER_ADDRESSES_FILE = "address.csv"
try:
    df = pd.read_csv(HACKER_ADDRESSES_FILE)
    hacker_addresses = set(df['address'].astype(str).str.replace('"', '').str.lower())
except Exception as e:
    print("Error reading CSV file:", e)
    exit()

# Latest Major Exchange Addresses (2024-2025)
EXCHANGE_ADDRESSES = {
    "Binance": "0x28c6c06298d514db089934071355e5743bf21d60",
    "Coinbase": "0x503828976D22510aad0201ac7EC88293211D23Da",
    "Kraken": "0x2910543af39aba0cd09dbb2d50200b3e800a63d2",
    "Gemini": "0xd24400ae8bfebb18ca49be86258a3c749cf46853",
    "Bitfinex": "0x876eabf441b2ee5b5b0554fd502a8e0600950cfa",
    "KuCoin": "0x2b5634c42055806a59e9107ed44d43c426e58258",
    "OKX": "0x6cc5f688a315f3dc28a7781717a9a798a59fda7b",
    "Gate.io": "0x0d0707963952f2fba59dd06f2b425ace40b492fe",
    "Bybit": "0xf89d7b9c864f589bbf53a82105107622b35eaa40",
    "Crypto.com": "0x6262998ced04146fa42253a5c0af90ca02dfd2a3",
    "Bitstamp": "0x00bdb5699745f5b860228c8f939abf1b9ae374ed",
    "Poloniex": "0x32be343b94f860124dc4fee278fdcbd38c102d88",
    "Bithumb": "0x88d34944cf554e9cccf4a24292d891f620e9c94f",
    "Upbit": "0x390de26d772d2e2005c6d1d24afc902bae37a4bb",
}

# Latest Major Bridge Addresses (2024-2025)
BRIDGE_ADDRESSES = {
    "Multichain": "0x13b432914a996b0a48695df9b2d701eda45ff264",
    "Synapse": "0x2796317b0ff8538f253012862c06787adfb8ceb6",
    "Stargate": "0x296f55f8fb28e498b858d0bcda06d955b2cb3f97",
    "cBridge": "0x841ce48f9446c8e281d3f1444cb859b4a6d0738c",
    "Hop Protocol": "0x3666f603cc164936c1b87e207f36beba4ac5f18a",
    "Thorchain": "0x42a5ed456650a09dc10ebc6361a7480fdd61f27b",
    "Avalanche Bridge": "0x8eb8a3b98659cce290402893d0123abb75e3ab28",
    "Arbitrum Bridge": "0x011b6e24ffb0b5f5fcc564cf4183c5bbbc96d515",
}

# Connect to Ethereum network
w3 = Web3(Web3.HTTPProvider(ETH_RPC_URL))
if not w3.isConnected():
    print("Failed to connect to Ethereum network!")
    exit()

print("Connected to Ethereum network.")

# Function to track transactions in real time
def track_transactions():
    while True:
        try:
            latest_block = w3.eth.block_number
            block = w3.eth.get_block(latest_block, full_transactions=True)
            
            for tx in block.transactions:
                from_address = tx["from"].lower()
                to_address = tx["to"].lower() if tx["to"] else None
                value = w3.from_wei(tx["value"], "ether")
                tx_hash = tx["hash"].hex()  # Get transaction hash

                # Alert if a hacker address sends ETH to an exchange or bridge
                if from_address in hacker_addresses and (to_address in EXCHANGE_ADDRESSES.values() or to_address in BRIDGE_ADDRESSES.values()):
                    print(f"🚨 Hacker Transaction Detected!")
                    print(f"🟢 From (Hacker): {from_address}")
                    print(f"🔵 To (Exchange/Bridge): {to_address}")
                    print(f"💰 Amount: {value} ETH")
                    print(f"🔗 Tx Hash: https://etherscan.io/tx/{tx_hash}")
                    print("-" * 50)

            time.sleep(10)  # Check every 10 seconds
        except Exception as e:
            print("Error:", e)
            time.sleep(10)

if __name__ == "__main__":
    track_transactions()
