import requests
import time
import json
import os
import re
import math
import csv
import inspect
import time
import random
from eth_abi.abi import decode as decode_abi
from typing import Union, Dict
from decimal import Decimal
from web3 import Web3
from datetime import datetime
from datetime import timezone
from datetime import timedelta
from moralis import evm_api
from eth_utils import keccak
from urllib.parse import urlencode
from goplus.token import Token
from typing import Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from threading import Lock
from web3.exceptions import ContractLogicError

class RateLimiter:
    def __init__(self, max_calls, period):
        self.lock = Lock()
        self.max_calls = max_calls
        self.period = period
        self.calls = []

    def acquire(self):
        with self.lock:
            now = time.time()
            self.calls = [t for t in self.calls if now - t < self.period]
            if len(self.calls) >= self.max_calls:
                time_to_wait = self.period - (now - self.calls[0])
                time.sleep(time_to_wait)
            self.calls.append(time.time())

scan_rate_limiter = RateLimiter(max_calls=2, period=1.0)

#pass smellytokens2025 or Smelly@tokens2025 (infura)
ETHERSCAN_API_KEY = "YI5IUPU68CCB5AWVF8TP3T2BKY9FXW4QUH"
BSCSCAN_API_KEY = "IZJXB2H1EYWQ41PSSXC5HE4FMPS58KKPCZ"
#MORALIS_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjhmNjk4NzNlLTUzZjktNGUxNi05Yzk2LTViODM0OGQ3Y2RmMSIsIm9yZ0lkIjoiNDQzMjE0IiwidXNlcklkIjoiNDU2MDA5IiwidHlwZUlkIjoiZDc3NTRlMTctYWNhZi00NWU1LWJlMjEtZDQ0MjM4ZGMxZDZhIiwidHlwZSI6IlBST0pFQ1QiLCJpYXQiOjE3NDUzMTI1ODEsImV4cCI6NDkwMTA3MjU4MX0.TjBrdK-dzF9t5nRmQImzIenGGYussYsaqzKr7E_oXsc"
MORALIS_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjgyMzgzZjIwLWVkODktNGYzNC1iN2RlLTk3ZThhMjMxMDM0MSIsIm9yZ0lkIjoiNDY1NTk3IiwidXNlcklkIjoiNDc4OTk5IiwidHlwZUlkIjoiMjVkYjA2NmEtNzc3NS00YTE1LTljNWQtYmI3ZGQzMTdjMzg3IiwidHlwZSI6IlBST0pFQ1QiLCJpYXQiOjE3NTU0Mzk3NzIsImV4cCI6NDkxMTE5OTc3Mn0.ucabc9dxy2WqBDsHlvd1gjL76MTxazFdZ2JDwsS57Ds"
DE_FI_KEY = "01f0c32c50f8423fbecda88260014f1e"
INFURA = "604e06a07adb4e4990bc4779bf8f4fa6" 
GOLDRUSH = "cqt_rQggFbfcQcgR3vMG74KGdk4fpVxq"
#url = "https:///v3/604e06a07adb4e4990bc4779bf8f4fa6"

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
#keccak256("Transfer(address,address,uint256)")

GOOD_TOKEN_ADDRESS = "0x55d398326f99059fF775485246999027B3197955"
BAD_TOKEN_ADDRESS = "0x15b874ADB2a0505579C46138Fb260a40A4BdFA94"
BAD_TOKEN_ADDRESS2 = "0x1d12b80341e40f763503117a2a57eababd4040c2" #OPEN dao token

BASE_URL_BSC = "https://api.bscscan.com/api"
BASE_URL_ETH = "https://api.etherscan.io/api"

#RPC_BSC = "https://bsc-dataseed.binance.org/"
RPC_BSC = "https://rpc.ankr.com/bsc/593a18aac4d0ae56b4f6dfcc2785e56d01515b0bcd30d6d52c9645b65cd1df95"
RPC_ETH = f"https://mainnet.infura.io/v3/{INFURA}"

# Common pair ABI
PAIR_ABI = json.loads("""
[
  {"inputs":[],"name":"getReserves","outputs":[
    {"type":"uint112","name":"reserve0"},
    {"type":"uint112","name":"reserve1"},
    {"type":"uint32","name":"blockTimestampLast"}],
    "stateMutability":"view","type":"function"},
  {"inputs":[],"name":"token0","outputs":[{"type":"address"}],"stateMutability":"view","type":"function"},
  {"inputs":[],"name":"token1","outputs":[{"type":"address"}],"stateMutability":"view","type":"function"}
]
""")

# Stablecoin references
STABLECOINS = {
    "eth": {
        "usdc": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
        "usdt": "0xdAC17F958D2ee523a2206206994597C13D831ec7"   # USDT
    },
    "bsc": {
        "busd": "0xe9e7cea3dedca5984780bafc599bd69add087d56",  # BUSD
        "usdt": "0x55d398326f99059ff775485246999027b3197955"   # USDT
    }
}

# Known reference pairs for resolving token → USD
REFERENCE_PAIRS = {
    "eth": {
        "weth_usdc": {
            "pair": "0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc",  # USDC/WETH
            "token0": STABLECOINS["eth"]["usdc"],  # USDC
            "token1": "0xC02aaA39b223FE8D0A0E5C4F27eAD9083C756Cc2",  # WETH
            "token0_decimals": 6,
            "token1_decimals": 18
        }
    },
    "bsc": {
        "wbnb_busd": {
            "pair": "0x1b96b92314c44b159149f7e0303511fb2fc4774f",  # BUSD/WBNB
            "token0": STABLECOINS["bsc"]["busd"],  # BUSD
            "token1": "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c",  # WBNB
            "token0_decimals": 18,
            "token1_decimals": 18
        }
    }
}


GRAPHQL_URL = "https://api.thegraph.com/subgraphs/name/uniswap/uniswap-v2"
DEBUG = True