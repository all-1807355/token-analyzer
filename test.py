import requests
import time
import json
import os
import re
from web3 import Web3
from datetime import datetime
#from moralis import evm_api
from eth_utils import keccak
from urllib.parse import urlencode
from goplus.token import Token

#pass smellytokens2025 or Smelly@tokens2025 (infura)
ETHERSCAN_API_KEY = "YI5IUPU68CCB5AWVF8TP3T2BKY9FXW4QUH"
BSCSCAN_API_KEY = "IZJXB2H1EYWQ41PSSXC5HE4FMPS58KKPCZ"
MORALIS_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjhmNjk4NzNlLTUzZjktNGUxNi05Yzk2LTViODM0OGQ3Y2RmMSIsIm9yZ0lkIjoiNDQzMjE0IiwidXNlcklkIjoiNDU2MDA5IiwidHlwZUlkIjoiZDc3NTRlMTctYWNhZi00NWU1LWJlMjEtZDQ0MjM4ZGMxZDZhIiwidHlwZSI6IlBST0pFQ1QiLCJpYXQiOjE3NDUzMTI1ODEsImV4cCI6NDkwMTA3MjU4MX0.TjBrdK-dzF9t5nRmQImzIenGGYussYsaqzKr7E_oXsc"
DE_FI_KEY = "01f0c32c50f8423fbecda88260014f1e"
INFURA = "604e06a07adb4e4990bc4779bf8f4fa6" 
#url = "https:///v3/604e06a07adb4e4990bc4779bf8f4fa6"

TRANSFER_TOPIC = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
#keccak256("Transfer(address,address,uint256)")

GOOD_TOKEN_ADDRESS = "0x55d398326f99059fF775485246999027B3197955"
BAD_TOKEN_ADDRESS = "0x15b874ADB2a0505579C46138Fb260a40A4BdFA94"
BAD_TOKEN_ADDRESS2 = "0x1d12b80341e40f763503117a2a57eababd4040c2" #OPEN dao token

BASE_URL_BSC = "https://api.bscscan.com/api"
BASE_URL_ETH = "https://api.etherscan.io/api"

RPC_BSC = "https://bsc-dataseed.binance.org/"
RPC_ETH = "https://cloudflare-eth.com"

DEBUG = True

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
            name = bytearray.fromhex(result[2:]).decode(errors='ignore').rstrip('\x00')
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
    debug_print(f"✅ Contract: {contract_name}")
    debug_print(f"🔧 Compiler: {compiler_version}")
    debug_print(f"📄 License: {license_type}")
    debug_print(f"🧠 Verified: {is_verified}")
    debug_print(f"🌀 Proxy: {is_proxy}")
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
                        "time_delay_seconds": age_seconds,
                        "block_delay": value
                    }

            else:
                debug_print(f"No transactions were found in the first 100 blocks!")
                debug_print("🟢 Usually Safe (always DYOR!)\n")
                return
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

def get_latest_tx_hash(address: str, chain: str):
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
    return txs[0]["hash"] if txs else None

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
            'last_active_utc': last_time,
            'inactive_days': age_days
        }
    else:
        return None


def get_token_balance(token,account,chain):
    params = {
        'module': 'account',
        'action': 'tokenbalance',
        'contractaddress': token,
        'address': account,
        'tag': 'latest',
    }
    res = api_call(params,chain)
    return int(res['result']) if res['result'] else None

def token_transfers(token,page,chain):
    params = {
        'module': 'account',
        'action': 'tokentx',
        'contractaddress': token,
        'page': str(page),
        'offset': '100',
        'startblock': '0',
        'endblock': '999999999',
        'sort': 'asc',
    }

    res = api_call(params,chain)
    return res if res else None#['result'] if res['result'] else None

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


def get_tx_list(address: str, startblock: int, endblock: int, chain: str) -> list:
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

        return datetime.fromtimestamp(earliest_time)

    except Exception as e:
        debug_print(f"Error fetching transactions for {address}: {e}")
        return None



def get_unique_token_holders(token,chain):
    page = 1
    addresses = set()

    # Keep paginating until no more results
    while page < 10:
        transactions = token_transfers(token, page, chain)
        if transactions['status'] == '0' or not transactions['result']:
            break
        # Add both 'from' and 'to' addresses to the set
        for tx in transactions["result"]:
            addresses.add(tx["from"])
            addresses.add(tx["to"])

        page += 1
    holders = []
    debug_print(f"Number of holders: {len(addresses)}\n")
    return addresses
    for address in addresses:
        balance = get_token_balance(token, address)
        if balance > 0:
            holders.append(address)
        time.sleep(0.2)
    return holders
"""
def get_token_holders_moralis(token, chain):
    api_key = MORALIS_API_KEY
    params = {
    "chain": chain,
    "order": "DESC",
    "token_address": token
    }
    response = evm_api.token.get_token_owners(api_key=api_key,params=params)
    res = response["result"]
    owner_balances = [(entry['owner_address'], float(entry['balance'])) for entry in res]
    return owner_balances
"""
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

def holder_analysis(token,chain):
    """
    returns
    Owner/creator wallet contains < 5% of circulating token supply
    All other holders possess < 5% of circulating token supply
    Top 10 token holders possess < 70% of circulating token supply
    """
    total_c_supply = get_circulating_supply(get_coingecko_id_from_contract(token,chain))
    owner = get_owner(token,chain)
    if owner == None:
        debug_print("Couldn't find owner, using creator\n")
        owner = get_creator(token,chain)
    #if owner != creator:
    #    debug_print("owner is not the original creator\nowner: {owner}\ncreator:{creator}")
    debug_print(f"Owner/creator address: {owner}")
    owner_balance = get_token_balance(token,owner,chain)
    balance_percentage = (owner_balance / total_c_supply) * 100
    if balance_percentage > 5:
        debug_print(f'⚠️ Owner/creator wallet contains MORE than 5% of the total circulating token supply: {balance_percentage:.2f}%\n') 
    else:
        debug_print(f'✅ Owner/creator wallet contains LESS than 5% of the total circulating token supply: {balance_percentage:.2f}%\n') 
     
    #return
    holders = get_unique_token_holders(token,chain)
    #holders = get_token_holders_moralis(token)
    debug_print(f"Analyzing {len(holders)} unique holders...")
    howmany = 0
    flag = None
    for holder,bal in holders:
        if holder.lower() == owner.lower():
            continue  # Skip the owner

        #holder_balance = get_token_balance(token, holder)
        #holder_percentage = (holder_balance / total_c_supply) * 100
        holder_percentage = (bal / total_c_supply) * 100
        if holder_percentage > 5:
            debug_print(f'⚠️ Holder {holder} owns {holder_percentage:.2f}% of the total circulating token supply.')
            flag = True
            howmany += 1
    if not flag :
        debug_print("✅ Holder analysis complete, no issues have been found")
    else:
        debug_print(f"⚠️ Holder analysis complete, {howmany} holders out of {len(holders)} own more than 5% of the total supply")
    return holders

def top10_analysis(token: str,holders:list,chain: str):
    """
    holder_balances = []
    for holder in holders:
        if holder.lower() == get_owner(token).lower():
            continue  # Skip the owner
        try:
            balance = get_token_balance(token,holder)
            normalized_balance = balance #/ (10 ** 18)
            holder_balances.append((holder, normalized_balance))
        except Exception as e:
            debug_print(f"Error fetching balance for {holder}: {e}")
    """
    sorted_holders = sorted(holders, key=lambda x: x[1], reverse=True)
    top_10 = sorted_holders[:10]
    debug_print("Top 10 Holders (without the owner):")
    for addr, bal in top_10:
        debug_print(f"{addr}: {bal:.2f}")

    total_top_10 = sum(balance for _, balance in top_10)
    percentage = (total_top_10 / get_circulating_supply(get_coingecko_id_from_contract(token,chain))) * 100
    percentage_over_total = (total_top_10 / get_total_supply(token)) * 100
    
    debug_print(f"\nTop 10 holders control {percentage:.6f}% of the circulating supply.")
    if percentage < 70:
        debug_print("✅ Top 10 token holders possess LESS than 70% of circulating token supply")
    else:
        debug_print("⚠️ Top 10 token holders possess MORE than 70% of circulating token supply")

    debug_print(f"\nTop 10 holders control {percentage_over_total:.2f}% of the total supply")
    

def effective_slippage_rate(address,chain):
    """ (expected price - actual price)/expected price * 100 %"""
    latest_tx = get_latest_tx_hash(address,chain)
    if not latest_tx:
        raise Exception("No transactions found for token")

    logs = get_receipt_logs(latest_tx,chain)
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
        "tx_hash": latest_tx
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

def is_probably_locker(address,chain):
    keywords = ['lock', 'vesting', 'timelock', 'unlock', 'release', 'cliff']
    name = get_contract_info(address,chain)['contract_name']
    return any(k in name.lower() for k in keywords)

def calculate_locked_percentage(token, address_list, chain):
    locked_total = 0
    for address in address_list:
        balance = get_token_balance(token, address, chain)
        debug_print(f"Locker detected: {address} with balance: {balance}")
        locked_total += balance
        """try:
            if is_probably_locker(address):
                balance = get_token_balance(token, address)
                debug_print(f"Locker detected: {address} with balance: {balance}")
                locked_total += balance
        except Exception as e:
            debug_print(f"Error processing {address}: {e}")"""

    total_supply = get_total_supply(token,chain)
    locked_percent = (locked_total / total_supply) * 100 if total_supply > 0 else 0
    debug_print(f"\nTotal Locked Tokens: {locked_total}")
    debug_print(f"Total Supply: {total_supply}")
    debug_print(f"Locked Percentage: {locked_percent:.2f}%")
    return locked_percent

def find_lockers_by_methods(addresses,chain):
    lockers = set()
    with open("/home/amedeo/Desktop/code_tests/data/4bytes-master/locking_selectors_inverted.json", "r") as f:
        methods_list = json.load(f)
    lastblock = get_latest_block(chain)
    for addr in addresses:
        txs = get_tx_list(addr,lastblock - 100, lastblock)
        for tx in txs:
            input_data = tx.get("input", "")
            if input_data and len(input_data) >= 10:
                method = input_data[:10].lower()
                if method in methods_list:
                    lockers.add(tx.get("to", "").lower())
                    print("FOUND")
        #time.sleep(0.2)
    debug_print(lockers)
    return lockers

def owner_hasless_5_LP(token,chain):

    chain = chain.lower()
    
    if chain == "bsc":
        RPC_URL = RPC_BSC
        FACTORY_ADDR = Web3.to_checksum_address("0xca143ce32fe78f1f7019d7d551a6402fc5350c73")  # PancakeSwap V2
        BASE_PAIR_TOKEN = Web3.to_checksum_address("0xBB4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")  # WBNB
    elif chain == "ethereum":
        RPC_URL = RPC_ETH  # Replace with actual Infura/Alchemy URL
        FACTORY_ADDR = Web3.to_checksum_address("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f")  # Uniswap V2
        BASE_PAIR_TOKEN = Web3.to_checksum_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")  # WETH
    else:
        raise ValueError("Unsupported chain. Use 'bsc' or 'ethereum'.")
    
    web3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not web3.is_connected():
        raise ConnectionError(f"❌ Failed to connect to {chain} RPC.")

    TOKEN_ADDR = Web3.to_checksum_address(token)
    CREATOR_ADDR = Web3.to_checksum_address(get_creator(token))
    
    FACTORY_ABI = [
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

    PAIR_ABI = [
        {"constant": True, "inputs": [], "name": "totalSupply", "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
        {"constant": True, "inputs": [{"name": "", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "", "type": "uint256"}], "stateMutability": "view", "type": "function"},
    ]

    factory = web3.eth.contract(address=FACTORY_ADDR, abi=FACTORY_ABI)
    pair_address = factory.functions.getPair(TOKEN_ADDR, BASE_PAIR_TOKEN).call()

    if not web3.is_connected():
        raise Exception("Failed to connect")

    # ------- HELPER FUNCTION -------
    def to_percent(numer, denom):
        return float(numer) / float(denom) * 100 if denom > 0 else 0

    if pair_address == "0x0000000000000000000000000000000000000000":
        print("❌ No liquidity pair found for token and base pair.")
        return

    print("✅ Found LP pair:", pair_address)

    pair = web3.eth.contract(address=pair_address, abi=PAIR_ABI)
    total_lp = pair.functions.totalSupply().call()
    creator_lp = pair.functions.balanceOf(CREATOR_ADDR).call()

    pct = to_percent(creator_lp, total_lp)
    print(f"\n📊 Creator owns {pct:.4f}% of LP tokens")

    if pct < 5:
        print("✅ Creator holds less than 5% of liquidity.")
    else:
        print("⚠️ Creator holds MORE than 5% of the liquidity — potential risk!")


"""----------------------------------------"""

def extract_exact_function(source_code: str, function_name: str) -> list:
    """
    Extracts the full definition of a specific Solidity function by name.
    """
    pattern = re.compile(
        rf'(function\s+{re.escape(function_name)}\s*\([^\)]*\)\s*(public|external)?[^\{{]*\{{(?:[^{{}}]*|\{{[^{{}}]*\}})*\}})',
        re.DOTALL | re.IGNORECASE
    )
    return [match.group(0).strip() for match in pattern.finditer(source_code)]


def extract_function_context(source_code: str, keyword: str, lines=30):
    """
    Extracts a chunk of lines surrounding a keyword (used for logic checks).
    """
    snippets = []
    code_lines = source_code.splitlines()
    for i, line in enumerate(code_lines):
        if keyword.lower() in line.lower():
            start = max(0, i - 5)
            end = min(len(code_lines), i + lines)
            snippet = '\n'.join(code_lines[start:end])
            if snippet not in snippets:
                snippets.append(snippet)
    return snippets


def extract_functions_matching(source_code: str, pattern: str):
    """
    Extracts full Solidity functions that match a specific regex pattern.
    """
    func_pattern = re.compile(r'(function\s+[^\{]+\{(?:[^{}]*|\{[^{}]*\})*\})', re.DOTALL)
    matched_functions = []
    for match in func_pattern.findall(source_code):
        if re.search(pattern, match, re.IGNORECASE):
            matched_functions.append(match.strip())
    return matched_functions


def analyze_token_contract_with_snippets(source_code: str) -> dict:
    findings = {}
    normalized_code = source_code.lower()

    # 1. Mint function
    mint_funcs = extract_functions_matching(source_code, r'\b(mint|mintToken|minted)\b')
    findings['mint_function_detected'] = {'found': bool(mint_funcs), 'snippets': mint_funcs}

    # 2. Ownership renounced
    renounce_snippets = extract_exact_function(source_code, 'renounceOwnership')
    if not renounce_snippets:
        renounce_snippets = extract_function_context(source_code, 'owner = address(0)')
    findings['ownership_renounced'] = {'found': bool(renounce_snippets), 'snippets': renounce_snippets}

    # 3. Honeypot-like behavior
    honeypot_keywords = ['cantransfer', 'istransferallowed', 'onlywhitelisted']
    honeypot_snippets = []
    for keyword in honeypot_keywords:
        honeypot_snippets += extract_function_context(source_code, keyword)
    findings['is_honeypot_suspected'] = {'found': bool(honeypot_snippets), 'snippets': honeypot_snippets}

    # 4. Delayed trading (block number checks)
    delayed_snippets = extract_function_context(source_code, 'block.number')
    findings['delayed_trading_detected'] = {'found': bool(delayed_snippets), 'snippets': delayed_snippets}

    # 5. Cooldown timers
    cooldown_keywords = ['cooldown', 'lasttx', 'lastbuy']
    cooldown_snippets = []
    for keyword in cooldown_keywords:
        cooldown_snippets += extract_function_context(source_code, keyword)
    findings['transfer_cooldown_detected'] = {'found': bool(cooldown_snippets), 'snippets': cooldown_snippets}

    # 6. High tax detection (>5%)
    high_tax_snippets = []
    tax_patterns = [
        r'\b(_taxFee|totalFee|sellFee|buyFee|burnFee|transferFee|fee|Fee)\b\s*=\s*(\d+)\b'
    ]
    for pattern in tax_patterns:
        for match in re.finditer(pattern, source_code):
            try:
                value = int(match.group(2))
                if value > 0:
                    context = extract_function_context(source_code, match.group(1))
                    high_tax_snippets += context
            except ValueError:
                continue
    findings['high_tax_detected'] = {'found': bool(high_tax_snippets), 'snippets': high_tax_snippets}

    # 7. Blacklist / Whitelist logic
    bw_snippets = extract_function_context(source_code, 'blacklist') + extract_function_context(source_code, 'whitelist')
    findings['blacklist_or_whitelist_detected'] = {'found': bool(bw_snippets), 'snippets': bw_snippets}

    # 8. Trading disabled
    trading_snippets = extract_function_context(source_code, 'tradingOpen') + extract_function_context(source_code, 'tradingEnabled')
    findings['trading_disabled_possible'] = {'found': bool(trading_snippets), 'snippets': trading_snippets}

    # 🖨️ Formatted output
    print("\n====== 🔍 Token Smart Contract Analysis Report ======\n")
    for key, data in findings.items():
        title = key.replace('_', ' ').capitalize()
        status = "✅ Found" if data['found'] else "❌ Not Found"
        print(f"🔸 {title}: {status}")

        if data['found']:
            for i, snippet in enumerate(data['snippets'], 1):
                print(f"\n  --- Snippet {i} ---")
                print("  ------------------")
                for line in snippet.strip().splitlines():
                    print(f"  {line}")
        print("\n" + "-" * 50 + "\n")

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

def get_dexscreener_price_liquidity_volume(token_address):
    url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
    res = requests.get(url).json()
    pairs = res.get('pairs', [])

    if not pairs:
        return None

    top_pair = max(pairs, key=lambda p: float(p.get('liquidity', {}).get('usd', 0)))
    try:
        price = float(top_pair.get('priceUsd', 0))
        liquidity = float(top_pair['liquidity']['usd']) #LIQUIDITY POOL DEPTH (Total USD value of tokens locked in the most liquid pool)
        volume_24h = float(top_pair['volume']['h24'])
        return price, liquidity, volume_24h
    except (TypeError, ValueError):
        return None

def get_liquidity_to_marketcap_ratio(token_address, chain='bsc', verbose=False):
    # Step 1: Get CoinGecko ID
    coingecko_id = get_coingecko_id_from_contract(token_address, chain)
    supply = None

    # Step 2: Try CoinGecko for circulating supply
    if coingecko_id:
        supply = get_circulating_supply(coingecko_id)
        if verbose:
            print(f"CoinGecko ID: {coingecko_id}, Supply from CoinGecko: {supply}")

    if not supply:
        if verbose: print("Failed to get circulating supply from both sources.")
        return None

    # Step 3: Get price and liquidity from DEXScreener
    price_liquidity = get_dexscreener_price_liquidity_volume(token_address)
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

def get_volume_to_liquidity_ratio(token_address, verbose=False):
    data = get_dexscreener_price_liquidity_volume(token_address)
    if not data:
        if verbose:
            print("Failed to get DEX data for token.")
        return None

    price, liquidity, volume_24h = data
    ratio = volume_24h / liquidity if liquidity else 0

    if verbose:
        print(f"24h Volume: ${volume_24h:,.2f}")
        print(f"Liquidity: ${liquidity:,.2f}")
        print(f"Volume/Liquidity Ratio: {ratio:.4f}")

    return {
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
    info = get_contract_info(token)
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
    abi = info["abi"].json()

    with open("/home/amedeo/Desktop/code_tests/addresses-darklist.json") as f:
        data = json.load(f)
        address_blacklist = data.get("terms",[])

    with open("/home/amedeo/Desktop/code_tests/urls-darklist.json") as f:
        data = json.load(f)
        url_blacklist = data.get("terms", [])

    if chain == 'bsc':
        with open("/home/amedeo/Desktop/code_tests/bsc-blacklist.json") as f:
            data = json.load(f)
            scammers_blacklist = data.get("terms",[])
    elif chain == 'eth':
        with open("/home/amedeo/Desktop/code_tests/ethereum-blacklist.json") as f:
            data = json.load(f)
            scammers_blacklist = data.get("terms",[])

    for term in terms:
        if term in source_code:
            print(f"Found term: {term}")


    print(source_code)
    print(abi)
    return


"""----------------------------------------"""
import tempfile
from slither.slither import Slither
from slither.slither import Slither
from slither.detectors.abstract_detector import AbstractDetector
from slither.exceptions import SlitherError

def analyze_contract_source(source_code):
    if not os.path.isfile(source_code):
        raise FileNotFoundError(f"File not found: {source_code}")

    try:
        slither = Slither(source_code)

        analysis_report = {
            'contracts': [],
            'findings': []
        }

        # Contract-level info
        for contract in slither.contracts:
            contract_info = {
                'name': contract.name,
                'functions': [f.name for f in contract.functions],
                'modifiers': [m.name for m in contract.modifiers],
                'inheritance': [base.name for base in contract.inheritance],
            }
            analysis_report['contracts'].append(contract_info)

        # Run all detectors
        for detector_class in AbstractDetector.__subclasses__():
            detector = detector_class(slither)
            results = detector.detect()
            for result in results:
                analysis_report['findings'].append({
                    'title': result.title,
                    'description': result.description,
                    'impact': result.impact.name,
                    'confidence': result.confidence.name,
                    'elements': [str(e) for e in result.elements]
                })
    
        return analysis_report
    


    except SlitherError as e:
        return {'error': str(e)}
    
def patch_solidity_code(code: str, contract_name: str, target_version="^0.8.30") -> str:
    # 1. Replace pragma version
    code = re.sub(r'pragma solidity\s+[^;]+;', f'pragma solidity {target_version};', code, flags=re.IGNORECASE)

    # 2. Replace legacy constructor (function named after contract)
    code = re.sub(
        rf'function\s+{contract_name}\s*\(',
        'constructor(',
        code
    )

    # 3. Fix fallback function syntax (pre-0.6.0)
    code = re.sub(
        r'function\s*\(\)\s*public\s*payable\s*{',
        'fallback() external payable {',
        code
    )

    # 4. Remove visibility from constructors (public/internal)
    code = re.sub(
        r'(constructor\s*\([^\)]*\))\s*(public|internal)',
        r'\1',
        code
    )

    # 5. Replace internal constructors in non-abstract contracts with default visibility
    code = re.sub(
        r'constructor\s*\(\)\s*internal',
        'constructor()',
        code
    )

    # 6. Fix msg.sender to payable(msg.sender) where necessary
    code = re.sub(
        r'return\s+msg\.sender\s*;',
        'return payable(msg.sender);',
        code
    )

    # 7. (Optional) Add SPDX license if missing to avoid warnings
    if "SPDX-License-Identifier" not in code:
        code = "// SPDX-License-Identifier: UNLICENSED\n" + code

    return code



"""----------------------------------------"""


def main():
    print(get_contract_name(GOOD_TOKEN_ADDRESS,'bsc'))
    get_contract_info(GOOD_TOKEN_ADDRESS,'bsc')
    return
    info = get_contract_info(GOOD_TOKEN_ADDRESS)
    print(info)
    print(get_token_name(GOOD_TOKEN_ADDRESS))
    return
    original_source = info["source_code"]
    #print(original_source)
    updated_source = patch_solidity_code(original_source, info["contract_name"])
    with tempfile.NamedTemporaryFile(suffix=".sol", delete=False, mode='w') as temp_sol_file:
        temp_sol_file.write(updated_source)
        temp_sol_file_path = temp_sol_file.name

    print(analyze_contract_source(temp_sol_file_path))
    return
    security_checks(BAD_TOKEN_ADDRESS2)
    return
    get_volume_to_liquidity_ratio("0x25d887Ce7a35172C62FeBFD67a1856F20FaEbB00",True)
    get_liquidity_to_marketcap_ratio("0x25d887Ce7a35172C62FeBFD67a1856F20FaEbB00",'bsc',True)
    
    #delay_between_creation_and_trade(BAD_TOKEN_ADDRESS)
    return
    #get_unique_token_holders(BAD_TOKEN_ADDRESS)
    get_holder_age("0xaafda33fc191cf99e3c2f4eb2108ed892cc78fc4")
    return

    info = get_contract_info(BAD_TOKEN_ADDRESS2)
    analyze_token_contract_with_snippets(info["source_code"])
    #calculate_locked_percentage(BAD_TOKEN_ADDRESS, find_lockers_by_methods(holders))
    #find_lockers_by_methods(holders)
    #calculate_locked_percentage(BAD_TOKEN_ADDRESS,holders)
    return
    #SWAP ANALYSIS
    #debug_print(f"🚀 Starting swap analysis for token: {BAD_TOKEN_ADDRESS}")
    get_token_age(BAD_TOKEN_ADDRESS)
    
    #CONTRACT ANALYSIS
    debug_print(f"🚀 Starting contract analysis for token: {BAD_TOKEN_ADDRESS}")
    verify_contract(BAD_TOKEN_ADDRESS)
    if(get_owner(BAD_TOKEN_ADDRESS) == get_creator(BAD_TOKEN_ADDRESS)):
        debug_print("⚠️ Current owner is the creator of the contract - ownership not renounced\n")
    else:
        debug_print("✅ Current owner is NOT the creator of the contract - ownership not renounced\n")

    #HOLDER ANALYSIS
    #owner/creator wallet contains less than 5% of circulating token supply?
    #All other holders possess less than 5% of circulating token supply?
    debug_print(f"🚀 Starting holder analysis for token: {BAD_TOKEN_ADDRESS}")
    holders = holder_analysis(BAD_TOKEN_ADDRESS)
    debug_print(f"Total unique addresses holding the token: {len(holders)}")
    
    #Top 10 token holders possess less than 70% of circulating token supply?
    top10_analysis(BAD_TOKEN_ADDRESS,holders)

    #SWAP ANALYSIS
    #debug_print(f"🚀 Starting swap analysis for token: {BAD_TOKEN_ADDRESS}")
    get_token_age(BAD_TOKEN_ADDRESS)
    
    #CONTRACT ANALYSIS
    debug_print(f"🚀 Starting contract analysis for token: {GOOD_TOKEN_ADDRESS}")
    verify_contract(GOOD_TOKEN_ADDRESS)
    if(get_owner(GOOD_TOKEN_ADDRESS) == get_creator(GOOD_TOKEN_ADDRESS)):
        debug_print("⚠️ Current owner is the creator of the contract - ownership not renounced\n")
    else:
        debug_print("✅ Current owner is NOT the creator of the contract - ownership not renounced\n")

    #HOLDER ANALYSIS
    #owner/creator wallet contains less than 5% of circulating token supply?
    #All other holders possess less than 5% of circulating token supply?
    debug_print(f"🚀 Starting holder analysis for token: {GOOD_TOKEN_ADDRESS}")
    holders = holder_analysis(GOOD_TOKEN_ADDRESS)
    debug_print(f"Total unique addresses holding the token: {len(holders)}")
    
    #Top 10 token holders possess less than 70% of circulating token supply?
    top10_analysis(GOOD_TOKEN_ADDRESS,holders)

    debug_print("all done, bye!\n")
    return

if __name__ == '__main__':
    main()

"""
import os, re, json

import os
import re
import json

def extract_locking_selectors(signatures_dir, output_file):
    keywords = [
        "lock", "locktokens", "lockliquidity", "createlock", "addlock",
        "initializelock", "extendlock", "depositlock", "locklp",
        "lockvested", "lockvesting", "lockfunds", "setlock",
        "freeze", "freezelp", "timelock", "vest", "vesting", "schedule",
        "unlock", "release"
    ]
    pattern = re.compile(rf"\b({'|'.join(re.escape(k) for k in keywords)})\b", re.IGNORECASE)

    locking_funcs = {}
    for filename in os.listdir(signatures_dir):
        file_path = os.path.join(signatures_dir, filename)
        with open(file_path, "r", encoding="utf-8") as f:
            text_sig = f.read().strip()  # function signature like "lockTokens(address,uint256)"
            func_name = text_sig.split("(")[0].lower()  # extract function name
            if pattern.search(func_name):
                hex_sig = "0x" + filename  # prepend 0x to filename to get full hex signature
                locking_funcs[text_sig] = hex_sig

    with open(output_file, "w") as f:
        json.dump(locking_funcs, f, indent=2)
    
    print(f"✔ Found {len(locking_funcs)} locking-related functions. Saved to '{output_file}'.")
"""