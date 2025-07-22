import requests
import time
import json
import os
import re
import math
from web3 import Web3
from datetime import datetime
from moralis import evm_api
from eth_utils import keccak
from urllib.parse import urlencode
from goplus.token import Token
from typing import Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm


#pass smellytokens2025 or Smelly@tokens2025 (infura)
ETHERSCAN_API_KEY = "YI5IUPU68CCB5AWVF8TP3T2BKY9FXW4QUH"
BSCSCAN_API_KEY = "IZJXB2H1EYWQ41PSSXC5HE4FMPS58KKPCZ"
MORALIS_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjhmNjk4NzNlLTUzZjktNGUxNi05Yzk2LTViODM0OGQ3Y2RmMSIsIm9yZ0lkIjoiNDQzMjE0IiwidXNlcklkIjoiNDU2MDA5IiwidHlwZUlkIjoiZDc3NTRlMTctYWNhZi00NWU1LWJlMjEtZDQ0MjM4ZGMxZDZhIiwidHlwZSI6IlBST0pFQ1QiLCJpYXQiOjE3NDUzMTI1ODEsImV4cCI6NDkwMTA3MjU4MX0.TjBrdK-dzF9t5nRmQImzIenGGYussYsaqzKr7E_oXsc"
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
RPC_ETH = "https://cloudflare-eth.com"

DEBUG = False

"""----------------------------------------"""
#HELPER FUNCTIONS
def debug_print(*args, **kwargs):
    """
    Print only if global DEBUG flag is set to True
    """
    if DEBUG:
        print(*args,**kwargs)

def api_call(params: dict, chain: str = 'eth'):
    """Helper method to perform api calls - Used for DRY

    Args:
        params (dict): Parameters for the API call to insert in the URL.
        chain (str): Used to switch between BscScan and Etherscan.

    Returns:
        Any: Parsed JSON 'result' from the API response, or None on failure
    """    

    if chain == 'bsc':
        params['apikey'] = BSCSCAN_API_KEY
        base = BASE_URL_BSC
    elif chain == 'eth':
        params['apikey'] = ETHERSCAN_API_KEY
        base = BASE_URL_ETH
    url = f"{base}?{urlencode(params)}"
    try:
        res = requests.get(url)#, timeout=10)
        res.raise_for_status()
        return res.json()
    except (requests.RequestException, ValueError) as e:
        print(f"API call error: {e}")
        return None


"""----------------------------------------"""

def get_token_name(token_address: str, chain: str) -> str:
    """
    Returns the token name

    Args:
        token_address (string): Address of the input token.
        chain (string): Chain on which the token is deployed.

    Returns:
        string: Name of the token
    """
    params = {
        'module': 'proxy',
        'action': 'eth_call',
        'to': token_address,
        'data': '0x06fdde03',  # keccak("name()")[:4]
        'tag': 'latest',
    }
    result = api_call(params,chain).get("result", None)
    if result and result != '0x':
        try:
            raw = bytes.fromhex(result[2:])
            name = Web3.to_text(raw[64:]).rstrip('\x00')
            #name = bytearray.fromhex(result[2:]).decode(errors='ignore').rstrip('\x00')
            return name
        except Exception:
            return "[Invalid name()]"
    
    # Fallback if function doesn't exist
    return "[name() not implemented]"

def get_contract_info(contract_address: str, chain: str) -> dict:
    """
    Returns basic information about the input smart contract

    Args:
        contract_address (str): Token smart contract to analyze.
        chain (str): Chain on which the token is deployed.

    Returns:
        dict: Token name, compiler version, license, if the contract is verified, if the contract is a proxy.
    """
    params = {
        'module': 'contract',
        'action': 'getsourcecode',
        'address': contract_address,
    }
    res = api_call(params,chain)

    if res.get('status') != '1' or res.get('message') != 'OK' or not res.get('result'):
        debug_print(f"❌ Failed to retrieve contract info for {contract_address}: {res.get('result')}")
        return None

    result = res['result'][0]
    abi = result.get('ABI', '')
    is_verified = abi != 'Contract source code not verified'

    if not is_verified:
        debug_print(f"❌ Contract at {contract_address} is not verified.")
        return None  # or return a reduced structure if you still want info

    # Extract data
    source_code = result.get('SourceCode', '')
    contract_name = result.get('ContractName', '')
    compiler_version = result.get('CompilerVersion', '')
    license_type = result.get('LicenseType', '')
    is_proxy = result.get('Proxy', '0') == '1'
    implementation_address = result.get('Implementation', '')

    # Debug prints only if verified
    #debug_print(f"✅ Contract: {contract_name}")
    #debug_print(f"🔧 Compiler: {compiler_version}")
    #debug_print(f"📄 License: {license_type}")
    #debug_print(f"🧠 Verified: {is_verified}")
    #debug_print(f"🌀 Proxy: {is_proxy}")
    if is_proxy:
        debug_print(f"➡️  Implementation: {implementation_address}")

    return {
        "source_code": source_code,
        "contract_name": contract_name,
        "compiler_version": compiler_version,
        "license_type": license_type,
        "verified": is_verified,
        "is_proxy": is_proxy,
        "implementation": implementation_address,
        "abi": abi
    }

def is_contract_verified(contract: str, chain: str) -> int:
    """
    Checks if a smart contract for a token is verified

    Args:
        contract (str): The smart contract to analyze
        chain (str): The chain on which the token is deployed

    Returns:
        int: A True/False int value
    """
    params = {
        "module": "contract",
        "action": "getabi",
        "address": contract,
    }
    res = api_call(params,chain)
    if int(res["status"]):
        debug_print(f"✅ Contract source verified\n")
    else:
        debug_print(f"⚠️ Contract source NOT verified\n")
    return int(res["status"])

def get_contract_creation_tx(contract: str, chain: str) -> dict:
    """
    Retrieves the transaction that created the token

    Args:
        contract (str): The address of the smart contract
        chain (str): The chain on which the token is deployed

    Returns:
        dict: Hash, timestamp and block number of the transaction creating the token
    """
    params = {
        'module': 'contract',
        'action': 'getcontractcreation',
        'contractaddresses': contract,
    }
    res = api_call(params,chain)
    if res['status']=='1':
        return {
            'hash': res['result'][0]['txHash'],
            'timestamp': res['result'][0]["timestamp"],
            'blocknum': res['result'][0]['blockNumber']
        }    
    else: 
        return None

def get_creation_to_first_trade_delay(token: str, chain: str) -> dict:
    creation = get_contract_creation_tx(token,chain)
    creation_timestamp = creation["timestamp"]
    creation_blocknum = creation["blocknum"]
    txs = get_tx_list(token,creation_blocknum,int(creation_blocknum)+99,chain)
    if txs:
        for item in txs:
            if item['timeStamp']:
                    trade_timestamp = datetime.fromtimestamp(int(item['timeStamp']))
                    creation_timestamp_dt = datetime.fromtimestamp(int(creation_timestamp))
                    debug_print(f"The creation timestamp is: {creation_timestamp_dt}\n")
                    debug_print(f"The timestamp of the first trade is: {trade_timestamp}\n")
                    age_seconds = (trade_timestamp - creation_timestamp_dt).total_seconds()
                    age_days = age_seconds // 86400
                    age_hours = (age_seconds % 86400) // 3600
                    age_minutes = (age_seconds % 3600) // 60
                    debug_print(f"The delay between the two timestamps is of: {age_days} days, {age_hours} hours, {age_minutes} minutes\n")
                    value = int(item["blockNumber"])-int(creation["blocknum"])
                    debug_print(f"The delay between the blocks for each is: {value}\n")
                    if 0 <= value < 5:
                        debug_print("🔴 Very Suspicious\n")
                    elif 5 <= value < 20:
                        debug_print("🟠 Possibly Suspicious\n")
                    elif 20 <= value < 100:
                        debug_print("🟡 Worth Investigating\n")
                    else:
                        debug_print("🟢 Usually Safe (always DYOR!)\n")
                    return {
                        "creation_date": creation_timestamp_dt.isoformat(),
                        "time_delay_seconds": age_seconds,
                        "block_delay": value
                    }

            else:
                debug_print(f"No transactions were found in the first 100 blocks!")
                debug_print("🟢 Usually Safe (always DYOR!)\n")
                return {
                    "creation_date": creation_timestamp_dt.isoformat(),
                    "time_delay_seconds": None,
                    "block_delay": None
                }
    else:
        debug_print(f"Error retrieving the list of transactions!")
        return None


def get_transaction_from_hash(hash: str, chain: str):
    params = {
        'module': 'proxy',
        'action': 'eth_getTransactionByHash',
        'txhash': hash,
    }
    res = api_call(params,chain)
    return res['result']['blockNumber'] if res['result'] else None

def get_latest_tx(address: str, chain: str):
    params = {
        "module": "account",
        "action": "tokentx",
        "contractaddress": address,
        "page": 1,
        "offset": 1,
        "sort": "desc",
    }
    res = api_call(params,chain)
    txs = res.get("result", [])
    return txs[0] if txs else None
    """
    EXAMPLE
    {'blockNumber': '14204129', 'timeStamp': '1641700024', 
    'hash': '0x4295f63d8cfad511c85b9bae78a3c84e41b570916dc409145bc3dbc740a585e2', 'nonce': '3',
    'blockHash': '0x3c997dd2c4660652e98275f150b3bbcaf5d00bd8c5f5e63bac2ca9655af67f7e', 
    'from': '0xabf2f1339f2387513019a5f8696f070abccc36f6', 
    'contractAddress': '0x2c78a165f1e52b021db82f337d61e8a1ef115f66', 
    'to': '0x000000000000000000000000000000000000dead', 
    'value': '223606797749978969639917', 
    'tokenName': 'Pancake LPs', 'tokenSymbol': 'Cake-LP',
    'tokenDecimal': '18', 'transactionIndex': '15', 'gas': '76450', 'gasPrice': '7000000000',
    'gasUsed': '35967', 'cumulativeGasUsed': '842785', 
    'input': 'deprecated', 'methodId': '0xa9059cbb', 'functionName': 
    'transfer(address dst, uint256 amount)', 'confirmations': '40494497'}
    """


def get_receipt_logs(hash: str, chain: str):
    params = {
        "module": "proxy",
        "action": "eth_getTransactionReceipt",
        "txhash": hash,
    }
    res = api_call(params,chain)
    return res["result"]["logs"] if res.get("result") else []

def parse_transfer_logs(logs):
    transfers = []
    for log in logs:
        if log["topics"][0].lower() == TRANSFER_TOPIC:
            try:
                from_addr = "0x" + log["topics"][1][-40:]
                to_addr = "0x" + log["topics"][2][-40:]
                token_address = log["address"]
                value = int(log["data"], 16)
                transfers.append({
                    "token": token_address,
                    "from": from_addr,
                    "to": to_addr,
                    "value": value
                })
            except Exception:
                continue
    return transfers

def check_swap(transfers):
    if len(transfers) < 2:
        debug_print("Not enough transfers! \n")
        return None
    for i in range(len(transfers)-1):
        t1,t2 = transfers[i],transfers[i+1]
        if t1["token"] != t2["token"]:
            return t1,t2 #the input and output token in the swap
    return None

def get_timestamp_from_blocknum(blocknum,chain):
    params = {
            'module': 'proxy',
            'action': 'eth_getBlockByNumber',
            'tag': blocknum,
            'boolean': 'true',
        }
    res = api_call(params,chain)
    return res['result']['timestamp'] if res['result'] else None

def get_token_age(token_address,chain):
    #Get creation transaction hash
    tx_hash = get_contract_creation_tx(token_address,chain)['hash']
    if(tx_hash == None):
        debug_print("error while getting tx hash")
        return
    blocknum = get_transaction_from_hash(tx_hash,chain)
    result = get_timestamp_from_blocknum(blocknum,chain)
    creation_timestamp = datetime.fromtimestamp(int(result,16))
    current_timestamp = datetime.now()

    #Compute token age
    age_seconds = (current_timestamp - creation_timestamp).total_seconds()
    #debug_print(creation_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
    #debug_print(current_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
    age_days = age_seconds // 86400
    age_hours = (age_seconds % 86400) // 3600
    age_minutes = (age_seconds % 3600) // 60
    debug_print(f"Token age: {age_days} days, {age_hours} hours, {age_minutes} minutes\n")
    return age_seconds

def last_active_age(token_address,chain):
    params = {
        'module': 'account',
        'action': 'txlist',
        'address': token_address,
        'startblock': 0,
        'endblock': 99999999,
        'page': 1,
        'offset': 1,
        'sort': 'desc',
    }

    res = api_call(params,chain)

    if res['status'] == '1' and res['result']:
        timestamp = int(res['result'][0]['timeStamp'])
        last_time = datetime.fromtimestamp(timestamp)
        now = datetime.now()
        age_days = (now - last_time).total_seconds() / 86400
        
        debug_print(f"Last transaction Hash: {res['result'][0]['hash']}")
        debug_print(f"Last Active Time (UTC): {last_time}")
        debug_print(f"Inactive for (days): {age_days:.2f}")
        
        return {
            'last_tx_hash': res['result'][0]['hash'],
            'last_active_utc': last_time.isoformat(),
            'inactive_days': age_days
        }
    else:
        return None


def get_token_balance_API(token,account,chain):
    params = {
        'module': 'account',
        'action': 'tokenbalance',
        'contractaddress': token,
        'address': account,
        'tag': 'latest',
    }
    res = api_call(params,chain)
    return int(res['result']) if res['result'] else None

def get_token_balance_web3(address: str, token: str, web3: Web3, abi: list) -> int:
    """
    Retrieves the balance of `address` for an ERC-20 `token` using `web3.py`.
    """
    try:
        contract = web3.eth.contract(address=Web3.to_checksum_address(token), abi=abi)
        balance = contract.functions.balanceOf(Web3.to_checksum_address(address)).call()
        return balance
    except Exception as e:
        print(f"⚠️ Error fetching balance for {address}: {e}")
        return 0



def get_latest_block(chain):
    if chain == 'eth':
        chain_id = 1
    elif chain == 'bsc':
        chain_id = 56
    params = {
        "chainid": chain_id,
        "module": "proxy",
        "action": "eth_blockNumber",
    }
    data = api_call(params,chain)
    if data.get("result"):
        return int(data["result"], 16)  # hex to int
    else:
        raise Exception("Failed to get latest block")


def get_tx_list(address: str, startblock: int, endblock, chain: str) -> list:
    """
    Retrieves a list of transactions for a given address between specified blocks.

    Args:
        address (str): The wallet or contract address.
        startblock (int): Starting block number.
        endblock (int): Ending block number.
        chain (str): Blockchain to use ('bsc' or 'eth').

    Returns:
        list: A list of transaction dicts, or an empty list if none found or on failure.
    """
    params = {
        "module": "account",
        "action": "txlist",
        "address": address,
        "startblock": startblock,
        "endblock": endblock,
        "sort": "asc",
    }

    response = api_call(params, chain)
    if response and response.get("status") == "1":
        return response.get("result", [])
    else:
        print(f"No transactions found or API error for address: {address}")
        return []


def get_holder_age(address,chain):
    try:
        debug_print(f"Fetching normal transactions for {address}")
        params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "page": 1,
            "offset": 1,
            "sort": "asc",
        }
        res_tx = api_call(params,chain)

        earliest_tx_time = None
        if res_tx.get("status") == "1" and res_tx.get("result"):
            first_tx = res_tx["result"][0]
            earliest_tx_time = int(first_tx["timeStamp"])
            debug_print(f"Earliest normal tx timestamp: {datetime.fromtimestamp(earliest_tx_time)}")
        else:
            debug_print("No normal transactions found")
    
    except Exception as e:
        debug_print(f"Error fetching transactions for {address}: {e}")
        return None
    #------------------------------------------------
    try:
        debug_print(f"Fetching token transactions for {address}")
        params_token = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "startblock": 0,
            "endblock": 99999999,
            "page": 1,
            "offset": 1,
            "sort": "asc",
            "apikey": BSCSCAN_API_KEY
        }
        res_token = requests.get(BASE_URL_BSC, params=params_token, timeout=10).json()

        earliest_token_tx_time = None
        if res_token.get("status") == "1" and res_token.get("result"):
            first_token_tx = res_token["result"][0]
            earliest_token_tx_time = int(first_token_tx["timeStamp"])
            debug_print(f"Earliest token tx timestamp: {datetime.fromtimestamp(earliest_token_tx_time)}")
        else:
            debug_print("No token transactions found")

        if earliest_tx_time and earliest_token_tx_time:
            earliest_time = min(earliest_tx_time, earliest_token_tx_time)
            debug_print(f"Using earliest timestamp from normal or token tx: {datetime.fromtimestamp(earliest_time)}")
        else:
            earliest_time = earliest_tx_time or earliest_token_tx_time
            if earliest_time:
                debug_print(f"Using earliest timestamp from one source: {datetime.fromtimestamp(earliest_time)}")
            else:
                debug_print("No transactions found at all")
                return None

        return datetime.fromtimestamp(earliest_time).isoformat()

    except Exception as e:
        debug_print(f"Error fetching transactions for {address}: {e}")
        return None

def get_unique_token_holders_web3(token_address: str, web3: Web3, abi: list,
                          from_block: int, to_block: int = 'latest',
                          step: int = 5000, max_workers: int = 10) -> dict:

    token_address = Web3.to_checksum_address(token_address)

    if isinstance(to_block, str) and to_block.lower() == 'latest':
        to_block = web3.eth.block_number

    contract = web3.eth.contract(address=token_address, abi=abi)
    balance_of = contract.functions.balanceOf

    all_addresses = set()

    print(f"📦 Scanning Transfer logs from block {from_block} to {to_block}...")
    for start in tqdm(range(from_block, to_block + 1, step)):
        end = min(start + step - 1, to_block)
        try:
            logs = web3.eth.get_logs({
                "fromBlock": start,
                "toBlock": end,
                "address": token_address,
                "topics": [TRANSFER_TOPIC]
            })

            for log in logs:
                if len(log["topics"]) >= 3:
                    from_addr = "0x" + log["topics"][1].hex()[-40:]
                    to_addr = "0x" + log["topics"][2].hex()[-40:]
                    all_addresses.add(from_addr.lower())
                    all_addresses.add(to_addr.lower())
        except Exception as e:
            print(f"⚠️ Failed to get logs from {start}-{end}: {e}")
            continue

    print(f"🔍 Found {len(all_addresses)} unique addresses. Checking balances...")

    holders = {}

    def check_balance(addr):
        try:
            balance = balance_of(Web3.to_checksum_address(addr)).call()
            return (addr, balance) if balance > 0 else None
        except:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(check_balance, addr): addr for addr in all_addresses}
        for future in tqdm(as_completed(futures), total=len(futures)):
            result = future.result()
            if result:
                addr, balance = result
                holders[addr] = balance

    print(f"✅ Found {len(holders)} holders with non-zero balances.")
    return holders

def get_unique_token_holders_API(token,chain):
    addresses = set()

    # Keep paginating until no more results
    while True:
        transactions = get_token_transfers(token, chain)
        if not transactions or transactions['status'] == '0' or not transactions['result']:
            break
        # Add both 'from' and 'to' addresses to the set
        for tx in transactions["result"]:
            from_addr = tx["from"].lower()
            to_addr = tx["to"].lower()
            if from_addr != "0x0000000000000000000000000000000000000000":
                addresses.add(from_addr)
            if to_addr != "0x0000000000000000000000000000000000000000":
                addresses.add(to_addr)
    
    debug_print(f"Number of holders: {len(addresses)}\n")
    return addresses

def get_unique_token_holders_moralis(token, chain):
    params = {
        "chain": chain,
        "order": "DESC",
        "token_address": token
    }
    response = evm_api.token.get_token_owners(api_key=MORALIS_API_KEY, params=params)
    res = response["result"]
    # Convert balance strings/floats to integers (rounded down)
    owner_balances = [(entry['owner_address'], int(float(entry['balance']))) for entry in res]
    return dict(owner_balances)

def is_hardcoded_owner(token,chain):
    privileged_keywords = ["owner", "admin", "dev", "fee", "wallet"]
    pattern = r'address\s+(?:public|private|internal)?\s*([a-zA-Z0-9_]+)\s*=\s*(0x[a-fA-F0-9]{40})'
    matches = re.findall(pattern, get_contract_info(token,chain)['source_code'])
    flag = False
    for var_name, eth_address in matches:
        if any(keyword in var_name.lower() for keyword in privileged_keywords):
            print("🚨 Hardcoded privileged address found:")
            print(f"   Variable: {var_name}")
            print(f"   Address: {eth_address}")
            flag = True
    if not flag:
        print("✅ Hardcoded privileged address NOT found")
    return flag

#HOLDER ANALYSIS
def get_owner(token,chain):
    functionnames = ["owner","getowner","getOwner","admin"]
    for function in functionnames:
        func = '0x' + keccak(text=function + '()').hex()[:8]
        #try to get contract's current owner 
        
        params = {
            'module': 'proxy',
            'action': 'eth_call',
            'to': token,
            'data': func,
        }
        res = api_call(params,chain)
        result = res.get('result','')
        if result and result != '0x':
            owner_address = '0x' + result[-40:]
            if owner_address != '0x0000000000000000000000000000000000000000':
                debug_print(f"The owner address is {owner_address.lower()}\n")
                return owner_address.lower()
            else:
                debug_print(f"The owner appears to be address 0x0000000000000000000000000000000000000000, ownerhip has probably been renounced or owner is hidden")
                
    return None
    
def get_creator(token,chain):
    params = {
        'module': 'contract',
        'action': 'getcontractcreation',
        'contractaddresses': token,
    }
    res = api_call(params,chain)
    debug_print(f"The contract creator is {res['result'][0]['contractCreator'].lower()}\n")
    return res['result'][0]['contractCreator'] if res['status']=='1' else None

def get_total_supply(token,chain):
    params = {
        'module': 'stats',
        'action': 'tokensupply',
        'contractaddress': token,
    }
    res = api_call(params,chain)
    return int(res['result']) if res['result'] else None

def holder_analysis(token,chain,holders,total_c_supply,web3: Web3, abi):
    """
    returns
    Owner/creator wallet contains < 5% of circulating token supply
    All other holders possess < 5% of circulating token supply
    Top 10 token holders possess < 70% of circulating token supply
    """
    #total_c_supply = get_circulating_supply(get_coingecko_id_from_contract(token, chain))
    #total_c_supply = get_circulating_supply_estimate(token,chain,holders)
    owner = get_owner(token, chain)
    if owner is None:
        debug_print("Couldn't find owner, using creator\n")
        owner = get_creator(token, chain)

    debug_print(f"Owner/creator address: {owner}")
    owner_balance = get_token_balance_web3(owner, token, web3,abi)
    owner_percentage = (owner_balance / total_c_supply) * 100
    owner_flag = owner_percentage > 5

    #if owner != creator:
    #    debug_print("owner is not the original creator\nowner: {owner}\ncreator:{creator}")
    #return
    #holders = get_unique_token_holders_moralis(token,chain)
    #holders = get_token_holders_moralis(token)
    debug_print(f"Analyzing {len(holders)} unique holders...")
    flagged_holders = []
    for holder, balance in holders.items():
        if holder.lower() == owner.lower():
            continue  # Skip the owner

        age = get_holder_age(holder,chain)
        percentage = (balance / total_c_supply) * 100

        # Add individual holder details only if they exceed threshold
        if percentage > 5:
            flagged_holders.append({
                'address': holder,
                'balance': balance,
                'age': age,
                'percentage_of_supply': percentage
            })

    result = {
        'owner': {
            'address': owner,
            'balance': owner_balance,
            'percentage_of_supply': owner_percentage,
            'exceeds_5_percent': owner_flag
        },
        'flagged_holders': flagged_holders,
        'summary': {
            'total_holders_checked': len(holders),
            'holders_exceeding_5_percent': len(flagged_holders),
            'compliant': len(flagged_holders) == 0
        }
    }

    return result

def top10_analysis(token: str, chain: str, holders: dict, total_circulating):
    """
    Returns a dictionary with:
    - top_10 holders (address, balance, percentage of supply)
    - percentage of circulating supply held by top 10
    - compliance flag for <70% rule
    """
    #total_circulating = get_circulating_supply(get_coingecko_id_from_contract(token, chain))
    #total_circulating = get_circulating_supply_estimate(token,chain,holders)
    total_supply = get_total_supply(token,chain)

    # Sort holders by balance
    sorted_holders = sorted(holders.items(), key=lambda x: x[1], reverse=True)
    top_10 = sorted_holders[:10]

    top_10_data = []
    total_top_10_balance = 0

    for addr, balance in top_10:
        percentage_circ = (balance / total_circulating) * 100 if total_circulating else 0
        top_10_data.append({
            'address': addr,
            'balance': balance,
            'percentage_of_circulating_supply': percentage_circ
        })
        total_top_10_balance += balance

    percentage_circ_total = (total_top_10_balance / total_circulating) * 100 if total_circulating else 0
    percentage_total_supply = (total_top_10_balance / total_supply) * 100 if total_supply else 0

    result = {
        'top_10_holders': top_10_data,
        'totals': {
            'total_top_10_balance': total_top_10_balance,
            'percentage_of_circulating_supply': percentage_circ_total,
            'percentage_of_total_supply': percentage_total_supply,
            'top_10_less_than_70_percent_circulating': percentage_circ_total < 70
        }
    }

    return result
    

def effective_slippage_rate(address,chain):
    """ (expected price - actual price)/expected price * 100 %"""
    latest_tx = get_latest_tx(address,chain)
    if not latest_tx:
        raise Exception("No transactions found for token")

    logs = get_receipt_logs(latest_tx['hash'],chain)
    #debug_print(logs)
    #debug_print(len(logs))
    transfers = parse_transfer_logs(logs)
    #debug_print(transfers)
    swap = check_swap(transfers)

    if not swap:
        raise Exception("Could not infer a swap from transfer logs")

    token_in, token_out = swap
    token_in_amt = float(token_in["value"] / 10 ** 18)  # Assumes 18 decimals
    token_out_amt = float(token_out["value"] / 10 ** 18)  # Assumes 18 decimals

    price_after = token_out_amt / token_in_amt if token_in_amt != 0 else None

    # --- Get price_before from previous swap ---
    # Fetch 2nd-latest transaction
    txs = fetch_latest_tx_list(address, chain, 2)
    if len(txs) < 2:
        raise Exception("Not enough transactions to infer price before")

    previous_tx = txs[1]["hash"]
    logs_prev = get_receipt_logs(previous_tx,chain)
    transfers_prev = parse_transfer_logs(logs_prev)
    prev_swap = check_swap(transfers_prev)

    if not prev_swap:
        raise Exception("Could not infer previous swap")

    token_in_prev, token_out_prev = prev_swap
    in_prev_amt = float(token_in_prev["value"] / 10 ** 18)
    out_prev_amt = float(token_out_prev["value"] / 10 ** 18)

    price_before = out_prev_amt / in_prev_amt if in_prev_amt != 0 else None 

    slippage = round(((price_before - price_after) / price_before) * 100, 4)

    return {
        "token_in": token_in["token"],
        "token_out": token_out["token"],
        "amount_in": token_in_amt,
        "amount_out": token_out_amt,
        "price_before": price_before,
        "price_after": price_after,
        "slippage_percent": slippage,
        "tx_hash": latest_tx['hash']
    }

def fetch_latest_tx_list(token_address, chain, count=2):
    params = {
        "module": "account",
        "action": "tokentx",
        "contractaddress": token_address,
        "page": 1,
        "offset": count,
        "sort": "desc",
    }
    res = api_call(params,chain)
    return res.get("result", [])

def is_contract(address,chain):
    params = {
        'module': 'proxy',
        'action': 'eth_getCode',
        'address': address,
        'tag': 'latest',
    }
    res = api_call(params,chain)
    code = res.get('result', '')
    #debug_print(code)
    return code and code != '0x'


def get_lp_pair(token: str, chain: str) -> str:
    """
    Returns the LP pair address for a token-base_token pair on the given chain.
    """
    chain = chain.lower()
    if chain == "bsc":
        RPC_URL = RPC_BSC
        factory_addr = Web3.to_checksum_address("0xca143ce32fe78f1f7019d7d551a6402fc5350c73")  # PancakeSwap V2
        base_pair_token = Web3.to_checksum_address("0xBB4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")  # WBNB
    elif chain == "ethereum":
        RPC_URL = RPC_ETH  # Replace with actual Infura/Alchemy URL
        factory_addr = Web3.to_checksum_address("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f")  # Uniswap V2
        base_pair_token = Web3.to_checksum_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")  # WETH
    else:
        raise ValueError("Unsupported chain. Use 'bsc' or 'ethereum'.")
    
    web3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not web3.is_connected():
        raise ConnectionError(f"❌ Failed to connect to {chain} RPC.")

    factory_abi = [
        {
            "constant": True,
            "inputs": [
                {"internalType": "address", "name": "", "type": "address"},
                {"internalType": "address", "name": "", "type": "address"},
            ],
            "name": "getPair",
            "outputs": [{"internalType": "address", "name": "", "type": "address"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        }
    ]

    pair_abi = [
        {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
        {"constant": True, "inputs": [{"name": "", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    ]

    factory = web3.eth.contract(address=factory_addr, abi=factory_abi)

    token_address = Web3.to_checksum_address(token)
    base_token_address = Web3.to_checksum_address(base_pair_token)
    pair_address = factory.functions.getPair(token_address, base_token_address).call()
    return pair_address,web3,pair_abi

    """
    def get_lp_holders(lp_address: str, web3: Web3, pair_abi: list,
                    from_block: int, to_block: int = 'latest',
                    step: int = 5000, max_workers: int = 10) -> dict:
        
        Scans on-chain Transfer logs for an LP token using web3.eth.get_logs to find current holders.

        Args:
            lp_address (str): LP token (pair) contract address
            web3 (Web3): Initialized Web3 instance
            pair_abi (list): ABI of the LP token contract
            from_block (int): Starting block number
            to_block (int | str): Ending block number or 'latest'
            step (int): Block batch size per call to avoid RPC limits
            max_workers (int): Number of threads for balanceOf() parallelization

        Returns:
            dict: {address: balance} of all LP token holders with non-zero balances
        
        lp_address = Web3.to_checksum_address(lp_address)
        if isinstance(to_block, str) and to_block.lower() == 'latest':
            to_block = web3.eth.block_number

        print(f"🔍 Scanning Transfer logs from block {from_block} to {to_block} in steps of {step}...")

        seen_addresses = set()
        current_from = from_block

        while current_from <= to_block:
            current_to = min(current_from + step - 1, to_block)
            try:
                logs = web3.eth.get_logs({
                    "fromBlock": current_from,
                    "toBlock": current_to,
                    "address": lp_address,
                    "topics": [TRANSFER_TOPIC]
                })

                print(f"📦 {len(logs)} logs in blocks {current_from}-{current_to}")

                for log in logs:
                    if len(log["topics"]) < 3:
                        continue
                    from_addr = Web3.to_checksum_address('0x' + log['topics'][1][-40:])
                    to_addr = Web3.to_checksum_address('0x' + log['topics'][2][-40:])
                    seen_addresses.update([from_addr, to_addr])

            except Exception as e:
                print(f"⚠️ Error fetching logs from {current_from} to {current_to}: {e}")
                time.sleep(3)

            current_from = current_to + 1

        print(f"🧾 Found {len(seen_addresses)} unique addresses.")

        return seen_addresses
    """

def get_lp_holders(lp_address: str, web3: Web3, pair_abi: list,
                   from_block: int, to_block: int = 'latest',
                   step: int = 5000, max_holders: int = 10,
                   min_step: int = 50) -> dict:
    """
    Efficiently gets LP holders with non-zero balances by scanning Transfer events in reverse.
    Only adds an address to the result if it has a positive balance.
    Stops early once `max_holders` are found.
    """
    TRANSFER_TOPIC = "0x" + Web3.keccak(text="Transfer(address,address,uint256)").hex()
    lp_address = Web3.to_checksum_address(lp_address)

    if isinstance(to_block, str) and to_block.lower() == 'latest':
        to_block = web3.eth.block_number

    contract = web3.eth.contract(address=lp_address, abi=pair_abi)
    holders = {}
    seen_addresses = set()
    current_to = to_block

    print(f"🔁 Scanning backwards from block {to_block} to {from_block} for up to {max_holders} LP holders...")

    while current_to >= from_block and len(holders) < max_holders:
        current_from = max(from_block, current_to - step + 1)
        try:
            logs = web3.eth.get_logs({
                "fromBlock": current_from,
                "toBlock": current_to,
                "address": lp_address,
                "topics": [TRANSFER_TOPIC]
            })

            for log in logs:
                if len(log["topics"]) >= 3:
                    try:
                        from_addr = Web3.to_checksum_address("0x" + log["topics"][1].hex()[-40:])
                        to_addr = Web3.to_checksum_address("0x" + log["topics"][2].hex()[-40:])

                        for addr in (from_addr, to_addr):
                            if addr not in seen_addresses:
                                seen_addresses.add(addr)
                                try:
                                    balance = contract.functions.balanceOf(addr).call()
                                    if balance > 0:
                                        holders[addr] = balance
                                        if len(holders) >= max_holders:
                                            break
                                except:
                                    continue
                    except:
                        continue

            print(f"🔎 Blocks {current_from}-{current_to}: {len(logs)} logs scanned, {len(holders)} valid LP holders")

        except Exception as e:
            if step <= min_step:
                print(f"🛑 Skipping block range {current_from}-{current_to} (min step reached): {e}")
                current_to -= step
                continue
            step = step // 2
            print(f"⚠️ Error: {e}. Reducing step to {step}")
            continue

        current_to = current_from - 1

    print(f"✅ Found {len(holders)} LP token holders with non-zero balances.")
    return holders


def analyze_lp_security(token: str, chain: str = 'bsc') -> Dict:
    # Supported chains
    chain_ids = {
        'eth': 1,
        'bsc': 56,
        'polygon': 137,
        'arbitrum': 42161,
        'avax': 43114
    }

    if chain not in chain_ids:
        raise ValueError(f"Unsupported chain: {chain}")
    
    chain_id = chain_ids[chain]

    print(f"🔍 Fetching token security data for token: {token} on chain: {chain}")
    
    # Fetch GoPlus data
    response = Token(access_token=None).token_security(chain_id=chain_id, addresses=[token])
    data = response.to_dict()  

    result = data.get("result", {})
    print(data)
    token_data = next(iter(result.values()), None)
    if not token_data:
        print("❌ Token data not found.")
        return {}

    lp_holders = token_data.get("lp_holders", [])
    lp_total_supply = float(token_data.get("lp_total_supply", 0))
    
    # Calculate % of LP locked
    locked_amount = sum(
        float(holder.get("balance", 0)) for holder in lp_holders if holder.get("is_locked")
    )
    percent_locked = (locked_amount / lp_total_supply) * 100 if lp_total_supply else 0

    # Check if ≥95% locked for ≥15 days
    now = datetime.now()
    long_term_locked = 0.0
    for holder in lp_holders:
        if holder.get("locked_detail"):
            for lock in holder["locked_detail"]:
                try:
                    end_time = datetime.fromisoformat(lock["end_time"].replace("Z", "+00:00"))
                    if (end_time - now).days >= 15:
                        long_term_locked += float(lock["amount"])
                except Exception as e:
                    print(f"⚠️ Failed parsing lock date: {e}")

    locked_95_for_15d = (long_term_locked / lp_total_supply) * 100 >= 95 if lp_total_supply else False

    # Creator info
    creator_percent_of_lp = float(token_data.get("creator_percent", 0)) * 100
    creator_under_5_percent = creator_percent_of_lp < 5
    owner_percent_of_lp = float(token_data.get("owner_percent", 0)) * 100
    owner_under_5_percent = owner_percent_of_lp < 5

    # Construct output
    liquidity_status = {
        "locked_liquidity_percent": round(percent_locked, 2),
        "locked_95_for_15_days": locked_95_for_15d,
        "liquidity_lock_status": "Secure" if locked_95_for_15d else "Unverified or Unlocked",
        "creator_under_5_percent": creator_under_5_percent,
        "creator_percent_of_lp": round(creator_percent_of_lp, 4),
        "owner_under_5_percent": owner_under_5_percent,
        "owner_percent_of_lp": round(owner_percent_of_lp, 4),
        "total_lp_supply": lp_total_supply,
        "lp_holders_count": len(lp_holders),
        "lp_holders": [
            {
                "address": holder["address"],
                "balance": float(holder["balance"]),
                "is_locked": bool(holder["is_locked"]),
                "percent": float(holder.get("percent", 0)),
                "tag": holder.get("tag", "")
            }
            for holder in lp_holders
        ]
    }

    # Optional print summary
    print(f"\n🔐 Locked Liquidity: {percent_locked:.2f}%")
    print(f"⏳ ≥95% Locked for ≥15 days: {'Yes' if locked_95_for_15d else 'No'}")
    print(f"👤 Creator holds <5% of LP: {'Yes' if creator_under_5_percent else 'No'}")
    print(f"📦 Total LP Supply: {lp_total_supply}")
    print(f"👥 LP Holders: {len(lp_holders)}")

    return liquidity_status


def compute_locked_lp_percentage(lockers: dict, lp_address: str, web3: Web3, pair_abi: list) -> float:
    """
    Computes the % of LP tokens held by known lock services.
    
    lockers: list of dicts like:
        [
            {"address": "0x...", "balance": 123},
            ...
        ]
    """

    lp_contract = web3.eth.contract(address=lp_address, abi=pair_abi)
    total_supply = lp_contract.functions.totalSupply().call()
    locked_total = sum(entry["balance"] for entry in lockers)

    if total_supply == 0:
        return 0.0

    locked_pct = (locked_total / total_supply) * 100
    return locked_pct

def find_all_lockers_and_burners(token, chain, holders: dict,web3):
    """
    Finds lockers and burners among LP token holders.

    Parameters
    ----------
    token : str
        The token contract address.
    chain : str
        The blockchain network.
    holders : dict
        Dictionary of holder addresses and their balances: {"0x...": balance, ...}

    Returns
    -------
    dict
        {
            "lockers": [ {"address": ..., "balance": ...}, ... ],
            "burners": [ {"address": ..., "balance": ...}, ... ]
        }
    """
    lockers = []
    burners = []
    seen_addresses = set()

    # First pass: check known lockers and burners
    for address, balance in holders.items():
        if islocker(address, chain):
            lockers.append({"address": address, "balance": balance})
            seen_addresses.add(address)
        elif isburner(address, chain):
            burners.append({"address": address, "balance": balance})
            seen_addresses.add(address)
    # Prepare set of addresses that haven't already been handled
    remaining_addresses = set(holders.keys()) - seen_addresses
    
    # Second pass: check for additional lockers using function signature heuristics
    additional_lockers = find_lockers_by_methods(token, chain, remaining_addresses)
    abi = get_contract_info(token,chain)['abi']
    for address in additional_lockers:
        if address not in seen_addresses:
            balance = get_token_balance_web3(address, token, web3,abi)
            if balance != 0:
                lockers.append({"address": address, "balance": balance})
                seen_addresses.add(address)

    return {
        "lockers": lockers,
        "burners": burners
    }

def compute_95pct_locked_or_burned(token_address: str,web3: Web3,pair_abi: list,chain: str,from_block: int,to_block: int = "latest") -> float:
    """
    Computes % of LP tokens locked or burned for >=15 days for the largest pool.
    Returns a float (e.g. 0.95 for 95%)
    """
    # 🔍 Step 1: Get LP pair for token (largest pool assumed)
    lp_address, _, _ = get_lp_pair(token_address, chain)
    print(f"🔗 LP Address: {lp_address}")

    # 🔎 Step 2: Get LP creation block for scanning LP holders
    creation = get_contract_creation_tx(lp_address, chain)
    creation_block = int(creation["blocknum"])
    print(f"📦 LP Creation Block: {creation_block}")

    # 🧾 Step 3: Get LP holders and balances
    holders = get_lp_holders(lp_address, web3, pair_abi, from_block=creation_block, to_block=to_block, chain=chain)
    
    if not holders:
        print("❌ No LP holders found.")
        return 0.0

    # 🔐 Step 4: Detect lockers and burners
    locker_info = find_all_lockers_and_burners(token_address, chain, holders,web3)

    # 🏦 Step 5: Get total LP token supply
    lp_contract = web3.eth.contract(address=lp_address, abi=pair_abi)
    total_supply = lp_contract.functions.totalSupply().call()

    if total_supply == 0:
        print("⚠️ Total LP supply is 0.")
        return 0.0

    # 🔍 Step 6: Evaluate lockers and burners
    locked_or_burned = 0

    # Evaluate lockers
    for locker in locker_info["lockers"]:
        addr = locker["address"]
        balance = locker["balance"]
        unlock_ts = get_unlock_timestamp(addr, lp_address, chain)  # ⬅️ You must implement this or use a known locker integration
        if is_locked_for_15_days_or_more(unlock_ts):
            locked_or_burned += balance

    # Evaluate burners (e.g., 0xdead)
    for burner in locker_info["burners"]:
        locked_or_burned += burner["balance"]

    ratio = locked_or_burned / total_supply
    print(f"📈 Locked/Burned LP Ratio: {ratio * 100:.2f}%")
    return ratio

def is_locked_for_15_days_or_more(unlock_timestamp: int) -> bool:
    """
    Returns True if tokens are locked for at least 15 more days.
    `unlock_timestamp == 0` implies permanently locked.
    """
    if unlock_timestamp == 0:
        return True
    unlock_time = datetime.utc_from_timestamp(unlock_timestamp)
    return unlock_time > datetime.now() + datetime.timedelta(days=15)

def get_unlock_timestamp(locker_address: str, lp_token_address: str, chain: str, web3: Web3) -> int:
    """
    Dynamically infers the unlock timestamp of LP tokens locked in a contract.
    It does this by analyzing the contract's ABI and probing known unlock method names.
    """
    locker_address = Web3.to_checksum_address(locker_address)

    # Step 1: Confirm it's a contract
    code = web3.eth.get_code(locker_address)
    if code in (b'', '0x'):
        print(f"❌ Address {locker_address} is not a contract.")
        return 0
    res = get_contract_info(lp_token_address,chain)
    # Step 2: Fetch ABI (from Etherscan/BscScan API or pre-cached)
    abi = res["abi"]
    if not abi:
        print(f"⚠️ Could not fetch ABI for {locker_address}")
        return 0

    contract = web3.eth.contract(address=locker_address, abi=abi)

    # Step 3: Probe methods to find unlock time
    for method in ["getUnlockTime","unlockTime","getReleaseTime","releaseTime","lockedUntil","lockEnd","getLockEndTime"]:
        try:
            fn = getattr(contract.functions, method)
            # Try with token param first (if needed)
            try:
                unlock_time = fn(lp_token_address).call()
            except:
                unlock_time = fn().call()
            # Must be a plausible future timestamp
            if unlock_time > int(time.time()):
                print(f"✅ Unlock time for {locker_address} from `{method}`: {unlock_time}")
                return unlock_time
        except Exception:
            continue

    print(f"⚠️ No usable unlock method found for {locker_address}")
    return 0

def find_lockers_by_methods(token: str, chain: str, addresses: set[str]) -> set[str]:
    """
    Returns a set of addresses that have used known locking-related function selectors.
    Also prints matched selectors and their method names.
    """
    lockers = set()

    # Load known selectors as dict: selector -> method name
    with open("/home/amedeo/Desktop/code_tests/data/4bytes-master/locking_selectors_inverted.json", "r") as f:
        selector_to_method = json.load(f)  # dict: e.g. { "0xa9059cbb": "transfer(address,uint256)" }

    # Get contract creation info
    creation = get_contract_creation_tx(token, chain)
    creation_blocknum = int(creation["blocknum"])

    for addr in addresses:
        if addr == "0x0000000000000000000000000000000000000000":
            continue

        txs = get_tx_list(addr, creation_blocknum, 'latest', chain)  # You should implement this per chain

        for tx in txs:
            input_data = tx.get("input", "")
            if input_data and len(input_data) >= 10:
                selector = input_data[:10].lower()
                if selector in selector_to_method:
                    method_name = selector_to_method[selector]
                    lockers.add(tx.get("to", "").lower())
                    print(f"🟢 Found locker via method {selector} ({method_name}) at {tx.get('to', '')}")
                    break  # One match is enough per address

    return lockers


def isburner(address,chain):
    known_burn = {
    "0x0000000000000000000000000000000000000000",
    "0x000000000000000000000000000000000000dEaD",
    "0x0000000000000000000000000000000000000001",
    "0x000000000000000000000000000000000000000d",
    "0x0000000000000000000000000000000000001000",
    }
    address = address.lower()
    chain = chain.lower()

    if address in known_burn:
        return True  # ✅ Known burn address
    
    txs = get_tx_list(address,0,'latest',chain)
    for tx in txs:
        if tx.get("from", "").lower() == address:
            return False  # ❌ Has sent a transaction
    
    token_txs = get_token_transfers(address, chain)
    for tx in token_txs:
        if tx.get("from", "").lower() == address:
            return False  # ❌ Has sent tokens

    return True

def get_token_transfers(token,chain):
    params = {
        'module': 'account',
        'action': 'tokentx',
        'contractaddress': token,
        'startblock': 0,
        'endblock': 'latest',
        'sort': 'asc',
    }

    res = api_call(params,chain)
    return res["result"] if res and "result" in res else None#['result'] if res['result'] else None


def islocker(address,chain):
    #UNICRYPT
    known_lockers = {
        "eth" : {
            "unicrypt_v4" : "0x6a76da1eb2cbe8b0d52cfe122c4b7f0ca5a940ef",
            "unicrypt_v3" : "0xFD235968e65B0990584585763f837A5b5330e6DE",
            "unicrypt_v2_uniswap" : "0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214",
            "unicrypt_v2_sushiswap" : "0xED9180976c2a4742C7A57354FD39d8BEc6cbd8AB",
            "unicrypt_vesting" : "0xDba68f07d1b7Ca219f78ae8582C213d975c25cAf"
        },
        "bsc" : {
            "unicrypt_v3" : "0xfe88DAB083964C56429baa01F37eC2265AbF1557",
            "unicrypt_v1_pancakeswap" : "0xc8B839b9226965caf1d9fC1551588AaF553a7BE6",
            "unicrypt_v2_pancakeswap" : "0xC765bddB93b0D1c1A88282BA0fa6B2d00E3e0c83",
            "unicrypt_v2_uniswap" : "0x7229247bD5cf29FA9B0764Aa1568732be024084b",
            "unicrypt_julswap" : "0x1f23742D882ace96baCE4658e0947cCCc07B6a75",
            "unicrypt_biswap" : "0x74dEE1a3E2b83e1D1F144Af2B741bbAFfD7305e1",
            "unicrypt_vesting" : "0xeaEd594B5926A7D5FBBC61985390BaAf936a6b8d",
            "team_finance" : "0x0c89c0407775dd89b12918b9c0aa42bf96518820",
            "UNCX_locker" : "0xC765bddB93b0D1c1A88282BA0fa6B2d00E3e0c83"
        },
        "solana" : "pinklock, check for locks on pinksale.finance"
    }
    found = False
    for locker in known_lockers[chain]:
        if address == locker:
            print(f"found a match in the locker database: {address}")
            found = True
            return found
    
    #check if address is cotract or not
    #if get_contract_info(address,chain)["source_code"] != None:
        #score +=1 
    
    #score = 0
    return False

def owner_hasless_5_LP(token,chain):

    pair_address,web3,pair_abi = get_lp_pair(token,chain)

    # ------- HELPER FUNCTION -------
    def to_percent(numer, denom):
        return float(numer) / float(denom) * 100 if denom > 0 else 0

    if pair_address == "0x0000000000000000000000000000000000000000":
        print("❌ No liquidity pair found for token and base pair.")
        return

    print("✅ Found LP pair:", pair_address)

    pair = web3.eth.contract(address=pair_address, abi=pair_abi)
    total_lp = pair.functions.totalSupply().call()
    creator = Web3.to_checksum_address(get_creator(token, chain))
    creator_lp = pair.functions.balanceOf(creator).call()

    pct = to_percent(creator_lp, total_lp)
    print(f"\n📊 Creator owns {pct:.4f}% of LP tokens")

    if pct < 5:
        print("✅ Creator holds less than 5% of liquidity.")
    else:
        print("⚠️ Creator holds MORE than 5% of the liquidity — potential risk!")


"""----------------------------------------"""

def extract_all_functions(source_code: str):
    pattern = re.compile(r'(function\s+[^\{]+\{(?:[^{}]*|\{[^{}]*\})*\})', re.DOTALL)
    return [match.strip() for match in pattern.findall(source_code)]

def analyze_token_contract_with_snippets(source_code: str) -> dict:
    findings = {}
    normalized_code = source_code.lower()
    funcs = extract_all_functions(normalized_code)

    # Keyword categories
    keyword_categories = {
        'mint_function_detected': [
            'mint', 'minttoken', 'minted', 'mining', 'claim', 'reward', 'gift', 'bonus', 'earn', 'airdrop', 'unlock',
            'tokenclaim', 'tokendrop', 'mintnft', 'airdropnft', 'claimnft', 'promoClaim', 'promotionbonus',
            'joingiveaway', 'claimgiveaway', 'claimoffer', 'getspecialoffer'
        ],
        'ownership_renounced': [
            'renounceownership', 'owner = address(0)', 'official', 'auth', 'verify', 'confirm', 'secure', 'safeguard',
            'officialclaim', 'officiallaunch'
        ],
        'is_honeypot_suspected': [
            'cantransfer', 'istransferallowed', 'onlywhitelisted', 'reward', 'connect', 'verify',
            'securetransfer', 'securewallet', 'cryptoconnect', 'cryptostart'
        ],
        'delayed_trading_detected': [
            'block.number', 'starttrading', 'enabletrading'
        ],
        'transfer_cooldown_detected': [
            'cooldown', 'lasttx', 'lastbuy'
        ],
        'high_tax_detected': [
            '_taxfee', 'totalfee', 'sellfee', 'buyfee', 'burnfee', 'transferfee', 'fee', 'stake', 'earn', 'profit', 
            'swap', 'exchange', 'deposit', 'withdraw', 'trading'
        ],
        'blacklist_or_whitelist_detected': [
            'blacklist', 'whitelist'
        ],
        'trading_disabled_possible': [
            'tradingopen', 'tradingenabled'
        ],
        'other_suspicious_detected': [
            'ethairdrop', 'claimeth', 'converteth'
        ]
    }

    # Scan each function and categorize
    for category, keywords in keyword_categories.items():
        matching_funcs = []
        for func in funcs:
            if any(keyword in func for keyword in keywords):
                matching_funcs.append(func)
        findings[category] = {
            'found': bool(matching_funcs),
            'snippets': matching_funcs
        }

    # 🖨️ Formatted output
    """print("\n====== 🔍 Token Smart Contract Analysis Report ======\n")
    for key, data in findings.items():
        title = key.replace('_', ' ').capitalize()
        status = "OK! Found" if data['found'] else "X Not Found"
        #print(f"🔸 {title}: {status}")

        if data['found']:
            for i, snippet in enumerate(data['snippets'], 1):
                print(f"\n  --- Snippet {i} ---")
                print("  ------------------")
                for line in snippet.strip().splitlines():
                    print(f"  {line}")
        print("\n" + "-" * 50 + "\n")"""
    return findings


def get_coingecko_id_from_contract(contract_address, chain):
    chain_map = {
        'bsc': 'binance-smart-chain',
        'eth': 'ethereum'
    }
    if chain not in chain_map:
        raise ValueError(f"Unsupported chain: {chain}")

    url = f"https://api.coingecko.com/api/v3/coins/{chain_map[chain]}/contract/{contract_address}"
    res = requests.get(url)
    if res.status_code != 200:
        print(f"CoinGecko ID lookup failed: {res.status_code}")
        return None
    return res.json().get('id')

def get_circulating_supply(coingecko_id):
    url = f"https://api.coingecko.com/api/v3/coins/{coingecko_id}"
    res = requests.get(url)
    if res.status_code != 200:
        return None
    try:
        return float(res.json()['market_data']['circulating_supply'])
    except (KeyError, TypeError, ValueError):
        return None

def get_circulating_supply_estimate(token,chain,addresses = ''):
    if addresses == '':
        holders = get_unique_token_holders_moralis(token,chain)
    else:
        holders = addresses
    total_supply = get_total_supply(token,chain)
    c_supply = 0
    locked_or_burned_supply = 0
    for holder,balance in tqdm(holders.items(), desc="Calculating Circulating Supply", unit="address"):
        print(holder)
        if islocker(holder,chain) or isburner(holder,chain):
            locked_or_burned_supply += balance
        else:
            c_supply += balance
    
    print(total_supply)
    print(locked_or_burned_supply)
    return total_supply - locked_or_burned_supply

def get_dexscreener_price_liquidity_volume(token_address):
    url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
    res = requests.get(url).json()
    pairs = res.get('pairs', [])

    if not pairs:
        print(f"ERROR: No liquidity pair found!\n")
        return None

    top_pair = max(pairs, key=lambda p: float(p.get('liquidity', {}).get('usd', 0)))
    try:
        price = float(top_pair.get('priceUsd', 0))
        liquidity = float(top_pair['liquidity']['usd']) #LIQUIDITY POOL DEPTH (Total USD value of tokens locked in the most liquid pool)
        volume_24h = float(top_pair['volume']['h24'])
        return price, liquidity, volume_24h
    except (TypeError, ValueError):
        return None

def get_liquidity_to_marketcap_ratio(token_address, price_liquidity, chain, holders, verbose=False):
    # Step 1: Get CoinGecko ID
    coingecko_id = get_coingecko_id_from_contract(token_address, chain)
    supply = None

    # Step 2: Try CoinGecko for circulating supply
    if coingecko_id:
        #supply = get_circulating_supply(coingecko_id)
        supply = get_circulating_supply_estimate(token_address,chain,holders)
        if verbose:
            print(f"CoinGecko ID: {coingecko_id}, Supply from CoinGecko: {supply}")

    if not supply:
        if verbose: print("Failed to get circulating supply from both sources.")
        return None

    # Step 3: Get price and liquidity from DEXScreener
    #price_liquidity = get_dexscreener_price_liquidity_volume(token_address)
    if not price_liquidity:
        if verbose: print("Failed to get DEXScreener price or liquidity.")
        return None

    price, liquidity, volume_24h = price_liquidity
    market_cap = supply * price
    ratio = liquidity / market_cap if market_cap else 0

    if verbose:
        print(f"Price: ${price}")
        print(f"Liquidity: ${liquidity}")
        print(f"Market Cap: ${market_cap}")
        print(f"Liquidity to Market Cap Ratio: {ratio:.4f}")

    return {
        'price_usd': price,
        'circulating_supply': supply,
        'market_cap_usd': market_cap,
        'liquidity_usd': liquidity,
        'liquidity_to_market_cap_ratio': ratio
    }

def get_volume_to_liquidity_ratio(price_liquidity, verbose=False):
    #price_liquidity = get_dexscreener_price_liquidity_volume(token_address)
    if not price_liquidity:
        if verbose:
            print("Failed to get DEX data for token.")
        return None

    price, liquidity, volume_24h = price_liquidity
    ratio = volume_24h / liquidity if liquidity else 0

    if verbose:
        print(f"24h Volume: ${volume_24h:,.2f}")
        print(f"Liquidity: ${liquidity:,.2f}")
        print(f"Volume/Liquidity Ratio: {ratio:.4f}")

    return {
        'price_usd': price,
        'volume_usd_24h': volume_24h,
        'liquidity_usd': liquidity,
        'volume_to_liquidity_ratio': ratio
    }
"""----------------------------------------"""

def security_checks(token,chain):
    """
    address darklist = A list of addresses that deserve to be accompanied by a warning.
    URL darklist = A list of URLs known to be fake, malicious, phishing.
    bsc-blacklist.json = list of bsc addresses known to be scams.
    ethereum-blacklist.json = list of eth addresses known to be scams.
    """
    info = get_contract_info(token,chain)
    code = info['source_code']
    """
    "source_code": source_code,
    "contract_name": contract_name,
    "compiler_version": compiler_version,
    "license_type": license_type,
    "verified": is_verified,
    "is_proxy": is_proxy,
    "implementation": implementation_address,
    "abi": abi
    """
    source_code = info.get("source_code")

    with open("/home/amedeo/Desktop/code_tests/data/addresses-darklist.json") as f:
        address_blacklist = json.load(f)

    with open("/home/amedeo/Desktop/code_tests/data/urls-darklist.json") as f:
        url_blacklist = json.load(f)

    if chain == 'bsc':
        with open("/home/amedeo/Desktop/code_tests/data/bsc-blacklist.json") as f:
            scammers_blacklist = json.load(f)
    elif chain == 'eth':
        with open("/home/amedeo/Desktop/code_tests/data/ethereum-blacklist.json") as f:
            scammers_blacklist = json.load(f)
    
    lowtoken = token.lower()
    matching_warnings = {}
    i = 0
    for address in address_blacklist:
        if address["address"].lower() == lowtoken:
            matching_warnings[i].append({
                "address": address['address'],
                "comment": address['comment']})
            print(f"Address: {address['address']}")
            print(f"Comment: {address['comment']}")
        i+=1

    matching_urls = {}
    urls = re.findall(r'https?://[^\s"\'<>]+', source_code)
    for blacklisted in url_blacklist:
        for found_url in urls:
            if blacklisted["id"] == found_url:
                print("Found URL inside the contract (known to be fake, malicious or a phishing url):", found_url)
                print("   → URL:", found_url)
                print("   → Reason:", blacklisted["comment"])
            matching_urls[found_url] = blacklisted["comment"]
    
    matching_addresses = {}
    if token in scammers_blacklist["tokens"]:
        print("Token address matches a suspicious address in the database!: ",token)
    found_addresses = re.findall(r'0x[a-fA-F0-9]{40}', source_code)
    for address in found_addresses:
        if address in scammers_blacklist["tokens"]:
            print("Found a suspicious address in the source code match with the database: ",address)
            matching_addresses["{token}"] = "{address}"

    return [
        matching_warnings,
        matching_urls,
        matching_addresses
    ]

# """
# import tempfile
# from slither.slither import Slither
# from slither.slither import Slither
# from slither.detectors.abstract_detector import AbstractDetector
# from slither.exceptions import SlitherError

# def analyze_contract_source(source_code):
#     if not os.path.isfile(source_code):
#         raise FileNotFoundError(f"File not found: {source_code}")

#     try:
#         slither = Slither(source_code)

#         analysis_report = {
#             'contracts': [],
#             'findings': []
#         }

#         # Contract-level info
#         for contract in slither.contracts:
#             contract_info = {
#                 'name': contract.name,
#                 'functions': [f.name for f in contract.functions],
#                 'modifiers': [m.name for m in contract.modifiers],
#                 'inheritance': [base.name for base in contract.inheritance],
#             }
#             analysis_report['contracts'].append(contract_info)

#         # Run all detectors
#         for detector_class in AbstractDetector.__subclasses__():
#             detector = detector_class(slither)
#             results = detector.detect()
#             for result in results:
#                 analysis_report['findings'].append({
#                     'title': result.title,
#                     'description': result.description,
#                     'impact': result.impact.name,
#                     'confidence': result.confidence.name,
#                     'elements': [str(e) for e in result.elements]
#                 })
    
#         return analysis_report
    


#     except SlitherError as e:
#         return {'error': str(e)}
    
# def patch_solidity_code(code: str, contract_name: str, target_version="^0.8.30") -> str:
#     # 1. Replace pragma version
#     code = re.sub(r'pragma solidity\s+[^;]+;', f'pragma solidity {target_version};', code, flags=re.IGNORECASE)

#     # 2. Replace legacy constructor (function named after contract)
#     code = re.sub(
#         rf'function\s+{contract_name}\s*\(',
#         'constructor(',
#         code
#     )

#     # 3. Fix fallback function syntax (pre-0.6.0)
#     code = re.sub(
#         r'function\s*\(\)\s*public\s*payable\s*{',
#         'fallback() external payable {',
#         code
#     )

#     # 4. Remove visibility from constructors (public/internal)
#     code = re.sub(
#         r'(constructor\s*\([^\)]*\))\s*(public|internal)',
#         r'\1',
#         code
#     )

#     # 5. Replace internal constructors in non-abstract contracts with default visibility
#     code = re.sub(
#         r'constructor\s*\(\)\s*internal',
#         'constructor()',
#         code
#     )

#     # 6. Fix msg.sender to payable(msg.sender) where necessary
#     code = re.sub(
#         r'return\s+msg\.sender\s*;',
#         'return payable(msg.sender);',
#         code
#     )

#     # 7. (Optional) Add SPDX license if missing to avoid warnings
#     if "SPDX-License-Identifier" not in code:
#         code = "// SPDX-License-Identifier: UNLICENSED\n" + code

#     return code
# """


"""----------------------------------------"""

def is_token_sellable(token_address: str, chain: str, test_amount_wei=10**18) -> bool:
    """
    Checks whether a token is sellable by simulating a swap on the appropriate DEX router.

    Args:
        token_address (str): The ERC20/BEP20 token address.
        chain (str): Either 'eth' or 'bsc'.
        test_amount_wei (int): Amount of tokens to test-sell in wei (default: 1 token assuming 18 decimals).

    Returns:
        bool: True if token appears sellable (not a honeypot), False otherwise.
    """
    token_address = Web3.to_checksum_address(token_address)
    if chain == "bsc":
        rpc_url = RPC_BSC
        router_addr = Web3.to_checksum_address("0x10ED43C718714eb63d5aA57B78B54704E256024E")  # PancakeSwap
        base_pair_token = Web3.to_checksum_address("0xBB4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")  # WBNB
    elif chain == "eth":
        rpc_url = RPC_ETH 
        router_addr = Web3.to_checksum_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")  # Uniswap
        base_pair_token = Web3.to_checksum_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")  # WETH
    else:
        raise ValueError("Unsupported chain. Use 'bsc' or 'ethereum'.")
    
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    ROUTER_ABI = json.loads(
        """[
            {
                "name": "getAmountsOut",
                "type": "function",
                "inputs": [
                    { "name": "amountIn", "type": "uint256" },
                    { "name": "path", "type": "address[]" }
                ],
                "outputs": [
                    { "name": "amounts", "type": "uint256[]" }
                ],
                "stateMutability": "view"
            }
        ]""")
    
    try:
        router = w3.eth.contract(address=router_addr, abi=ROUTER_ABI)
        path = [token_address, base_pair_token]
        # Simulate token -> ETH/BNB swap
        amounts_out = router.functions.getAmountsOut(test_amount_wei, path).call()
        output_amount = amounts_out[-1]
        return output_amount > 0
    except Exception as e:
        print(f"[!] Sell simulation failed: {e}")
        return False


"""----------------------------------------"""
def create_report():
    return
    
"""----------------------------------------"""

def analyze_token(token_address: str, chain: str, analysis_types: list = None) -> dict:
    """
    A comprehensive wrapper function that performs various analyses on a token and generates both human-readable 
    and JSON reports.

    Args:
        token_address (str): The address of the token to analyze
        chain (str): The blockchain network ('eth' or 'bsc')
        analysis_types (list, optional): List of analysis types to run. If None, runs all analyses.
                     Valid options: ['contract', 'holder', 'liquidity', 'security', 'lifecycle']

    Returns:
        dict: A dictionary containing all analysis results
    """
    if analysis_types is None:
        analysis_types = ['contract', 'holder', 'liquidity', 'security', 'lifecycle']
        filename_suffix = "full"
    else:
        filename_suffix = "_".join(analysis_types) if len(analysis_types) > 1 else analysis_types[0]    # Initialize results dictionary
    
    try:
        if chain == 'bsc':
            web3 = Web3(Web3.HTTPProvider(RPC_BSC))
        elif chain == 'eth':
            web3 = Web3(Web3.HTTPProvider(RPC_ETH))
    except:
        if not web3.is_connected():
            raise ConnectionError(f"❌ Failed to connect to {chain} RPC.")
    
    results = {
        'token_address': token_address,
        'chain': chain,
        'token_name': get_token_name(token_address, chain),
        'analyses': {}
    }

    # Initialize report string
    report = f"Token Analysis Report\n{'='*50}\n"
    report += f"Token: {results['token_name']} ({token_address})\n"
    report += f"Chain: {chain.upper()}\n\n"

    if 'contract' in analysis_types:
        print("\n🔍 Running contract analysis...")
        contract_info = get_contract_info(token_address, chain)
        sellable = is_token_sellable(token_address,chain)
        hardcoded = is_hardcoded_owner(token_address,chain)
        if contract_info:
            # return {
            #     "source_code": source_code,
            #     "contract_name": contract_name,
            #     "compiler_version": compiler_version,
            #     "license_type": license_type,
            #     "verified": is_verified,
            #     "is_proxy": is_proxy,
            #     "implementation": implementation_address,
            #     "abi": abi
            # }
            results['analyses']['contract'] = {
                'info': contract_info,
                'verified': contract_info['verified'],
                'owner': get_owner(token_address, chain),
                'creator': get_creator(token_address, chain),
                'is_proxy': contract_info['is_proxy'],
                'is_sellable': sellable,
                'is_hardcoded_owner': hardcoded
            }
            
            report += "Contract Analysis\n-----------------\n"
            report += f"Verified: {'OK!' if contract_info['verified'] else 'X'}\n"
            report += f"Owner Address: {results['analyses']['contract']['owner']}\n"
            report += f"Creator Address: {results['analyses']['contract']['creator']}\n"
            report += f"Is Proxy: {'Yes' if contract_info['is_proxy'] else 'No'}\n"
            report += f"Is sellable (no honeypot): {'Yes' if sellable else 'No'}\n"
            report += f"Is owner hardcoded: {'Yes' if hardcoded else 'No'}\n"

            if contract_info['source_code']:
                analysis = analyze_token_contract_with_snippets(contract_info['source_code'])
                results['analyses']['contract']['code_analysis'] = analysis
                
                report += "\nCode Analysis Findings:\n"
                for category, data in analysis.items():
                    if data['found']:
                        report += f"WARNING: {category.replace('_', ' ').title()}\n"
                        for snippet in data['snippets']:
                            report += f"  Code Snippet:\n{snippet}\n\n"

    if 'holder' in analysis_types:
        print("\n🔍 Running holder analysis...")

        """
            lp_address, web3, pair_abi = get_lp_pair(token_address,'bsc')
            creation = get_contract_creation_tx(token_address,'bsc')
            creation_timestamp = creation["timestamp"]
            creation_blocknum = int(creation["blocknum"])
            abi = get_contract_info(token_address,chain)['abi']
        """
        abi = results['analyses']['contract']['info']['abi'] if 'contract' in analysis_types else get_contract_info(token_address,chain)['abi']
        holders = get_unique_token_holders_moralis(token_address,chain)
        #holders = get_unique_token_holders_web3(token_address, web3, abi, creation_blocknum)
        #holders = get_unique_token_holders_API(token_address,chain)
        owner = results['analyses']['contract']['owner'] if 'contract' in results['analyses'] else get_owner(token_address, chain)
    
        report += "\nHolder Analysis\n--------------\n"
        report += f"Total Unique Holders: {len(holders)}\n"
        # Get owner's percentage if possible
        # coingecko_id = get_coingecko_id_from_contract(token_address, chain)
        # if coingecko_id:
        #     circ_supply = get_circulating_supply(coingecko_id)
        #     if circ_supply and owner:
        #         owner_balance = get_token_balance_web3(owner, token_address, Web3, results['analyses']['contract']['info']['abi'] if 'info' in results['analyses'] else get_contract_info(token_address,chain)['abi'])
        #         if owner_balance is not None:
        #             owner_percentage = (owner_balance / circ_supply) * 100
        
        enriched_dict = {}
        for address, balance in holders.items():
            age = get_holder_age(address,chain)  # You define this
            enriched_dict[address] = {
                "balance": balance,
                "age": age
            }

        results['analyses']['holders'] = {
            'total_holders': len(holders),
            'holders_list': enriched_dict,

            #'owner_percentage': f"{owner_percentage}\n" if owner_percentage else "0\n",  # Will be calculated if coingecko data is available
            'owner_is_hidden': False if owner else True,
        }
        total_c_supply = get_circulating_supply_estimate(token_address,chain,holders)
        results['analyses']['holders'].update(holder_analysis(token_address,chain,holders,total_c_supply,web3,abi))
        results['analyses']['holders'].update(top10_analysis(token_address,chain,holders,total_c_supply))
        # Owner section
        if 'owner' in results['analyses']['holders']:
            report += f"Owner Address: {results['analyses']['holders']['owner'].get('address', 'Unknown')}\n"
            report += f"Owner Balance: {results['analyses']['holders']['owner'].get('balance', 0):,} tokens\n"
            report += f"Owner Share: {results['analyses']['holders']['owner'].get('percentage_of_supply', 0):.2f}% of circulating supply\n"
            if results['analyses']['holders']['owner'].get('exceeds_5_percent', False):
                report += "⚠️ Owner holds MORE than 5% of circulating supply\n"
            else:
                report += "✅ Owner holds LESS than 5% of circulating supply\n"
        else:
            report += "⚠️ Owner information is not available (possibly hidden or unverified)\n"

        # Holder over 5% section
        if 'summary' in results['analyses']['holders']:
            total_checked = results['analyses']['holders']['summary'].get('total_holders_checked', 0)
            over_5 = results['analyses']['holders']['summary'].get('holders_exceeding_5_percent', 0)
            compliant = results['analyses']['holders']['summary'].get('compliant', False)

            report += f"Holders Checked (excluding owner): {total_checked}\n"
            report += f"Holders >5%: {over_5}\n"
            report += "✅ All holders under 5% threshold\n" if compliant else "⚠️ Some holders exceed 5% of supply\n"
        else:
            report += "⚠️ Holder analysis data is missing\n"

        # Top 10 holders section
        if 'top_10_holders' in results['analyses']['holders']:
            report += "\nTop 10 Token Holders:\n"
            for i, h in enumerate(results['analyses']['holders']['top_10_holders'], start=1):
                addr = h.get('address', 'Unknown')
                bal = h.get('balance', 0)
                pct = h.get('percentage_of_circulating_supply', 0)
                report += f"  {i}. {addr} — {bal:,} tokens ({pct:.2f}% of circulating supply)\n"

            totals = results['analyses']['holders'].get('totals', {})
            circ_pct = totals.get('percentage_of_circulating_supply', 0)
            total_pct = totals.get('percentage_of_total_supply', 0)
            less_than_70 = totals.get('top_10_less_than_70_percent_circulating', True)

            report += f"\nTop 10 Total Balance: {totals.get('total_top_10_balance', 0):,} tokens\n"
            report += f"Top 10 Share of Circulating Supply: {circ_pct:.2f}%\n"
            report += f"Top 10 Share of Total Supply: {total_pct:.2f}%\n"
            report += "✅ Top 10 holders control LESS than 70% of circulating supply\n" if less_than_70 else "⚠️ Top 10 holders control MORE than 70% of circulating supply\n"
        else:
            report += "⚠️ Top 10 holder analysis is not available\n"


            
    if 'liquidity' in analysis_types:
        print("\n🔍 Running liquidity analysis...")
        data = get_dexscreener_price_liquidity_volume(token_address)
        liquidity_pool_depth = data[1]
        holders = results['analyses']['holders']['holder_list'] if results['analyses']['holders']['holder_list'] else get_unique_token_holders_moralis(token_address,chain)
        liq_market_ratio = get_liquidity_to_marketcap_ratio(token_address,data,chain,holders)
        vol_liq_ratio = get_volume_to_liquidity_ratio(data)
        lp_address, web3, pair_abi = get_lp_pair(token_address,chain)
        creation = get_contract_creation_tx(GOOD_TOKEN_ADDRESS,'bsc')
        creation_timestamp = creation["timestamp"]
        creation_blocknum = int(creation["blocknum"])
        #liquidity_holders = get_lp_holders(lp_address, web3, pair_abi, from_block=creation_blocknum,to_block="latest")
        liquidity_status = analyze_lp_security(token_address,chain)
        liquidity_holders = liquidity_status["lp_holders"]

        lp_contract = web3.eth.contract(address=Web3.to_checksum_address(lp_address), abi=pair_abi)
        total_lp_supply = lp_contract.functions.totalSupply().call()
        
        if results.get("analyses", {}).get("contract") is not None:
            owner = results["analyses"]["contract"].get("owner") or get_owner(token_address, chain)
        else:
            owner = get_owner(token_address, chain)        
        #owner_lp_balance = lp_address.functions.balanceOf(owner).call()
        if results.get("analyses", {}).get("contract") is not None:
            creator = results["analyses"]["contract"].get("creator") or get_creator(token_address, chain)
        else:
            creator = get_creator(token_address, chain)
        results['analyses']['liquidity'] = {
            'liquidity_depth': liquidity_pool_depth,
            'liquidity_metrics': liq_market_ratio,
            'volume_metrics': vol_liq_ratio,
        }
        results.update(liquidity_status)
        
        report += "\nLiquidity Analysis\n-----------------\n"
        if liq_market_ratio:
            report += f"Market Cap: ${liq_market_ratio['market_cap_usd']:,.2f}\n"
            report += f"Liquidity: ${liquidity_pool_depth:,.2f}\n"
            report += f"Liquidity/MCap Ratio: {liq_market_ratio['liquidity_to_market_cap_ratio']:.4f}\n"
        if vol_liq_ratio:
            report += f"24h Volume/Liquidity Ratio: {vol_liq_ratio['volume_to_liquidity_ratio']:.4f}\n"
        if liquidity_status:
            report += f"Percentage of liquidity locked: {liquidity_status['locked_liquidity_percent']:.4f}\n"
            report += f"Was 95% of liquidity locked for more than 15 days?: {liquidity_status['locked_95_for_15_days']}\n"
            report += f"Secure\n" if {liquidity_status['locked_95_for_15_days']} else "Unverified or Unlocked\n"
            report += f"Creator owns under 5% of LP tokens: {liquidity_status['creator_under_5_percent']} ({liquidity_status['creator_percent_of_lp']})\n"
            report += f"Total supply of LP tokens: {liquidity_status['total_lp_supply']}\n"
            report += f"LP holders count: {liquidity_status['lp_holders_count']}\n"
            report += f"\r\n"
 
            report += f"Liquidity holders for {token_address}, ({results["token_name"] if results["token_name"] else get_token_name(token_address,chain)})\n"
            for holder in liquidity_holders:
                if holder["address"] == owner:
                    report += f"\r\nOwner {holder["address"]} holds {holder["balance"]} LP tokens\r\n"
                    owner_lp_balance = holder["balance"]
                    #check if owner holds less than 5% of liquidity...
                    if (owner_lp_balance / total_lp_supply) * 100 > 5:
                        if owner == creator:
                            print(f"WARNING: Owner/Creator holds over 5% of the liquidity")
                            report += f"WARNING: Owner/Creator holds over 5% of the liquidity"
                        print(f"WARNING: Owner holds over 5% of the liquidity")
                        report += f"WARNING: Owner holds over 5% of the liquidity"
                elif holder == creator:
                    report += f"\r\nCreator {holder["address"]} holds {holder["balance"]} LP tokens\r\n"
                    creator_lp_balance = holder["balance"]
                    #check if creator holds less than 5% of liquidity...
                    if (creator_lp_balance / total_lp_supply) * 100 > 5:
                        print(f"WARNING: Creator holds over 5% of the liquidity")
                        report += f"WARNING: Creator holds over 5% of the liquidity"
                else: report += f"\r\n{holder["address"]} holds {holder["balance"]} LP tokens\r\n"

    if 'security' in analysis_types:
        print("\n🔍 Running security checks...")
        security_result = security_checks(token_address, chain)
        results['analyses']['security'] = security_result
        check_types = ['Warnings', 'Suspicious URLs', 'Suspicious Addresses']

        report += "\nSecurity Analysis\n----------------\n"
        if any(security_result):
            for check_type, findings in zip(check_types, security_result):
                if findings:
                    report += f"WARNING: Found {len(findings)} {check_type}\n"
        else:
            report += "✅ No security issues found\n"

    if 'lifecycle' in analysis_types:
        print("\n🔍 Running lifecycle analysis analysis...")
        token_age = get_token_age(token_address, chain)
        creation_trade_delay = get_creation_to_first_trade_delay(token_address, chain)
        time_since_last_tx = last_active_age(token_address,chain)
        results['analyses']['lifecycle'] = {
            'token_age_seconds': token_age,
            'token_creation_date': creation_trade_delay["creation_date"],
            'creation_to_first_trade_seconds': creation_trade_delay["time_delay_seconds"],
            'creation_to_first_trade_blocks' : creation_trade_delay["block_delay"],
            'last_tx_hash': time_since_last_tx["last_tx_has"],
            'last_active_age': time_since_last_tx["last_active_utc"],
            'inactive_days': time_since_last_tx["inactive_days"]
        }

        report += "\nLifecycle Analysis\n-------------\n"
        report += f"Token Age: {token_age/86400:.2f} days\n"
        if creation_trade_delay:
            report += f"Time to First Trade: {creation_trade_delay['time_delay_seconds']/3600:.2f} hours\n"
            report += f"Blocks to First Trade: {creation_trade_delay['block_delay']}\n"
            report += f"Token Creation Date: {creation_trade_delay['creation_date']}\n"
        if time_since_last_tx:
            report += f"Last Active: {time_since_last_tx['last_active_utc']}\n"
            report += f"Days Since Last Activity: {time_since_last_tx['inactive_days']} days\n"
            report += f"Last Transaction Hash: {time_since_last_tx['last_tx_has']}\n"
        else:
            report += "⚠️ Could not determine last active transaction.\n"
    
   
    # Save the report to a file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f"token_analysis_{token_address[:8]}_{filename_suffix}_{timestamp}.txt"
    json_filename = f"token_analysis_{token_address[:8]}_{filename_suffix}_{timestamp}.json"
    
    with open(report_filename, 'w',encoding='utf-8') as f:
        f.write(report)
    
    print(results)
    with open(json_filename, 'w') as f:
        json.dump(results, f, indent=4)

    print(f"\n✅ Analysis complete!")
    print(f"📝 Report saved to: {report_filename}")
    print(f"📊 JSON data saved to: {json_filename}")
    
    return results

"""----------------------------------------"""

def main():
    analyze_token("0x223D94A76eA0d3F65c28F869f89B3739E73c1eC6",'bsc',['liquidity'])
    return
    lp_address, web3, pair_abi = get_lp_pair(BAD_TOKEN_ADDRESS2,'bsc')
    creation = get_contract_creation_tx(BAD_TOKEN_ADDRESS2,'bsc')
    creation_timestamp = creation["timestamp"]
    creation_blocknum = int(creation["blocknum"])
    abi = get_contract_info(BAD_TOKEN_ADDRESS2,'bsc')['abi']

    print(get_unique_token_holders_web3(BAD_TOKEN_ADDRESS2,web3,abi,creation_blocknum,'latest'))
    return
    analyze_token("0xfb5b838b6cfeedc2873ab27866079ac55363d37e",'bsc',['liquidity'])
    return
    lp_address, web3, pair_abi = get_lp_pair("0xfb5b838b6cfeedc2873ab27866079ac55363d37e",'bsc')
    creation = get_contract_creation_tx("0xfb5b838b6cfeedc2873ab27866079ac55363d37e",'bsc')
    creation_timestamp = creation["timestamp"]
    creation_blocknum = int(creation["blocknum"])
    holders = get_lp_holders(lp_address, web3, pair_abi, from_block=creation_blocknum,to_block=int(get_latest_tx(lp_address,'bsc')['blockNumber']))
    l_and_b_list = find_all_lockers_and_burners("0xfb5b838b6cfeedc2873ab27866079ac55363d37e",'bsc',holders)

    res = compute_locked_lp_percentage(l_and_b_list["lockers"],lp_address,web3,pair_abi)
    print(f"Locked LP %: {res}\n")
    for locker in l_and_b_list["lockers"]:
        print(f"Liquidity in {locker} is locked for 15 days or more: {is_locked_for_15_days_or_more(get_unlock_timestamp(locker,lp_address,'bsc',web3))}\n")
    #0xfb5b838b6cfeedc2873ab27866079ac55363d37e
    return

if __name__ == '__main__':
    main()
