import requests
import time
from datetime import datetime
from moralis import evm_api
from eth_utils import keccak
from urllib.parse import urlencode
from moralis import evm_api

#pass smellytokens2025
ETHERSCAN_API_KEY = "YI5IUPU68CCB5AWVF8TP3T2BKY9FXW4QUH"
BSCSCAN_API_KEY = "IZJXB2H1EYWQ41PSSXC5HE4FMPS58KKPCZ"
MORALIS_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjhmNjk4NzNlLTUzZjktNGUxNi05Yzk2LTViODM0OGQ3Y2RmMSIsIm9yZ0lkIjoiNDQzMjE0IiwidXNlcklkIjoiNDU2MDA5IiwidHlwZUlkIjoiZDc3NTRlMTctYWNhZi00NWU1LWJlMjEtZDQ0MjM4ZGMxZDZhIiwidHlwZSI6IlBST0pFQ1QiLCJpYXQiOjE3NDUzMTI1ODEsImV4cCI6NDkwMTA3MjU4MX0.TjBrdK-dzF9t5nRmQImzIenGGYussYsaqzKr7E_oXsc"

GOOD_TOKEN_ADDRESS = "0x55d398326f99059fF775485246999027B3197955"
BAD_TOKEN_ADDRESS = "0x15b874ADB2a0505579C46138Fb260a40A4BdFA94"

BASE_URL_BSC = "https://api.bscscan.com/api"
BASE_URL_ETH = "https://api.etherscan.io/api"

def verify_contract(contract):
    params = {
        "module": "contract",
        "action": "getabi",
        "address": contract,
        "apikey": BSCSCAN_API_KEY
    }
    url = f"{BASE_URL_BSC}?{urlencode(params)}"
    #print(url)
    res = requests.get(url).json()
    if int(res["status"]):
        print(f"✅ Contract source verified\n")
        #print(res)
    else:
        print(f"⚠️ Contract source NOT verified\n")
        #print(res)
    return int(res["status"])


def get_contract_creation_tx(contract):
    params = {
        'module': 'contract',
        'action': 'getcontractcreation',
        'contractaddresses': contract,
        'apikey': BSCSCAN_API_KEY
    }
    url = f"{BASE_URL_BSC}?{urlencode(params)}"
    res = requests.get(url).json()
    return res['result'][0]['txHash'] if res['status']=='1' else None

def get_transaction_from_hash(hash):
    params = {
        'module': 'proxy',
        'action': 'eth_getTransactionByHash',
        'txhash': hash,
        'apikey': BSCSCAN_API_KEY
    }
    url = f"{BASE_URL_BSC}?{urlencode(params)}"
    res = requests.get(url).json()
    return res['result']['blockNumber'] if res['result'] else None

def get_timestamp_from_blocknum(blocknum):
    params = {
            'module': 'proxy',
            'action': 'eth_getBlockByNumber',
            'tag': blocknum,
            'boolean': 'true',
            'apikey': BSCSCAN_API_KEY
        }
    url = f"{BASE_URL_BSC}?{urlencode(params)}"
    res = requests.get(url).json()
    return res['result']['timestamp'] if res['result'] else None

def get_token_age(token_address):
    
    #Get creation transaction hash
    tx_hash = get_contract_creation_tx(token_address)
    if(tx_hash == None):
        print("error while getting tx hash")
        return
    blocknum = get_transaction_from_hash(tx_hash)
    result = get_timestamp_from_blocknum(blocknum)
    creation_timestamp = datetime.fromtimestamp(int(result, 16))
    current_timestamp = datetime.now()

    #Compute token age
    age_seconds = (current_timestamp - creation_timestamp).total_seconds()
    #print(creation_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
    #print(current_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
    age_days = age_seconds // 86400
    age_hours = (age_seconds % 86400) // 3600
    age_minutes = (age_seconds % 3600) // 60
    print(f"Token age: {age_days} days, {age_hours} hours, {age_minutes} minutes\n")
    return

def get_token_balance(token,account):
    params = {
        'module': 'account',
        'action': 'tokenbalance',
        'contractaddress': token,
        'address': account,
        'tag': 'latest',
        'apikey': BSCSCAN_API_KEY
    }
    url = f"{BASE_URL_BSC}?{urlencode(params)}"
    res = requests.get(url).json()
    return int(res['result']) if res['result'] else None

def token_holders(token,page):
    params = {
        'module': 'account',
        'action': 'tokentx',
        'contractaddress': token,
        'page': str(page),
        'offset': '100',
        'startblock': '0',
        'endblock': '999999999',
        'sort': 'asc',
        'apikey': BSCSCAN_API_KEY
    }

    url = f"{BASE_URL_BSC}?{urlencode(params)}"
    res = requests.get(url).json()
    return res if res else None#['result'] if res['result'] else None

def get_unique_token_holders(token):
    page = 1
    addresses = set()

    # Keep paginating until no more results
    while page < 2:
        transactions = token_holders(token, page)
        if transactions['status'] == '0' or not transactions['result']:
            break
        # Add both 'from' and 'to' addresses to the set
        for tx in transactions["result"]:
            addresses.add(tx["from"])
            addresses.add(tx["to"])

        page += 1
    holders = [address for address in addresses if get_token_balance(token,address) > 0]
    #print(holders)
    return holders

def get_token_holders_moralis(token):
    api_key = MORALIS_API_KEY
    params = {
    "chain": "bsc",
    "order": "DESC",
    "token_address": token
    }
    response = evm_api.token.get_token_owners(api_key=api_key,params=params)
    res = response["result"]
    owner_balances = [(entry['owner_address'], float(entry['balance'])) for entry in res]
    return owner_balances

#HOLDER ANALYSIS
def get_owner(token):
    functionnames = ["owner","getowner","getOwner","admin"]
    for function in functionnames:
        func = '0x' + keccak(text=function + '()').hex()[:8]
        #try to get contract's current owner 
        params = {
            'module': 'proxy',
            'action': 'eth_call',
            'to': token,
            'data': func,
            'apikey': BSCSCAN_API_KEY
        }
        url = f"{BASE_URL_BSC}?{urlencode(params)}"
        #print(url)
        res = requests.get(url).json()
        result = res.get('result','')
        if result and result != '0x':
            owner_address = '0x' + result[-40:]
            if owner_address != '0x0000000000000000000000000000000000000000':
                print(f"The owner address is {owner_address.lower()}\n")
                return owner_address.lower()

    return None
    
def get_creator(token):
    params = {
        'module': 'contract',
        'action': 'getcontractcreation',
        'contractaddresses': token,
        'apikey': BSCSCAN_API_KEY
    }
    url = f"{BASE_URL_BSC}?{urlencode(params)}"
    res = requests.get(url).json()
    print(f"The contract creator is {res['result'][0]['contractCreator'].lower()}\n")
    return res['result'][0]['contractCreator'] if res['status']=='1' else None

def get_total_supply(token):
    params = {
        'module': 'stats',
        'action': 'tokensupply',
        'contractaddress': token,
        'apikey': BSCSCAN_API_KEY
    }
    url = f"{BASE_URL_BSC}?{urlencode(params)}"
    res = requests.get(url).json()
    return int(res['result']) if res['result'] else None

def holder_analysis(token):
    total_c_supply = get_circulating_supply(token)
    owner = get_owner(token)
    if owner == None:
        print("Couldn't find owner, using creator\n")
        owner = get_creator(token)
    #if owner != creator:
    #    print("owner is not the original creator\nowner: {owner}\ncreator:{creator}")
    print(f"Owner/creator address: {owner}")
    owner_balance = get_token_balance(token,owner)
    balance_percentage = (owner_balance / total_c_supply) * 100
    if balance_percentage > 5:
        print(f'⚠️ Owner/creator wallet contains MORE than 5% of the total circulating token supply: {balance_percentage:.2f}%\n') 
    else:
        print(f'✅ Owner/creator wallet contains LESS than 5% of the total circulating token supply: {balance_percentage:.2f}%\n') 
     
    #return
    #holders = get_unique_token_holders(token)
    holders = get_token_holders_moralis(token)
    print(f"Analyzing {len(holders)} unique holders...")
    howmany = 0
    flag = None
    for holder,bal in holders:
        if holder.lower() == owner.lower():
            continue  # Skip the owner

        #holder_balance = get_token_balance(token, holder)
        #holder_percentage = (holder_balance / total_c_supply) * 100
        holder_percentage = (bal / total_c_supply) * 100
        if holder_percentage > 5:
            print(f'⚠️ Holder {holder} owns {holder_percentage:.2f}% of the total circulating token supply.')
            flag = True
            howmany += 1
    if not flag :
        print("✅ Holder analysis complete, no issues have been found")
    else:
        print(f"⚠️ Holder analysis complete, {howmany} holders out of {len(holders)} own more than 5% of the total supply")
    return holders

def get_circulating_supply(token):
    params = {
        'module': 'stats',
        'action': 'tokenCsupply',
        'contractaddress': token,
        'apikey': BSCSCAN_API_KEY
    }
    url = f"{BASE_URL_BSC}?{urlencode(params)}"
    res = requests.get(url).json()
    return int(res['result']) if res['result'] else None

def top10_analysis(token: str,holders:list):
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
            print(f"Error fetching balance for {holder}: {e}")
    """
    sorted_holders = sorted(holders, key=lambda x: x[1], reverse=True)
    top_10 = sorted_holders[:10]
    print("Top 10 Holders (without the owner):")
    for addr, bal in top_10:
        print(f"{addr}: {bal:.2f}")

    total_top_10 = sum(balance for _, balance in top_10)
    percentage = (total_top_10 / get_circulating_supply(token)) * 100

    print(f"\nTop 10 holders control {percentage:.6f}% of the circulating supply.")
    if percentage < 70:
        print("✅ Top 10 token holders possess LESS than 70% of circulating token supply")
    else:
        print("⚠️ Top 10 token holders possess MORE than 70% of circulating token supply")

"""----------------------------------------"""

def main():
    #SWAP ANALYSIS
    #print(f"🚀 Starting swap analysis for token: {BAD_TOKEN_ADDRESS}")
    get_token_age(BAD_TOKEN_ADDRESS)
    
    #CONTRACT ANALYSIS
    print(f"🚀 Starting contract analysis for token: {BAD_TOKEN_ADDRESS}")
    verify_contract(BAD_TOKEN_ADDRESS)
    if(get_owner(BAD_TOKEN_ADDRESS) == get_creator(BAD_TOKEN_ADDRESS)):
        print("⚠️ Current owner is the creator of the contract - ownership not renounced\n")
    else:
        print("✅ Current owner is NOT the creator of the contract - ownership not renounced\n")

    #HOLDER ANALYSIS
    #owner/creator wallet contains less than 5% of circulating token supply?
    #All other holders possess less than 5% of circulating token supply?
    print(f"🚀 Starting holder analysis for token: {BAD_TOKEN_ADDRESS}")
    holders = holder_analysis(BAD_TOKEN_ADDRESS)
    print(f"Total unique addresses holding the token: {len(holders)}")
    
    #Top 10 token holders possess less than 70% of circulating token supply?
    top10_analysis(BAD_TOKEN_ADDRESS,holders)

    #SWAP ANALYSIS
    #print(f"🚀 Starting swap analysis for token: {BAD_TOKEN_ADDRESS}")
    get_token_age(BAD_TOKEN_ADDRESS)
    
    #CONTRACT ANALYSIS
    print(f"🚀 Starting contract analysis for token: {GOOD_TOKEN_ADDRESS}")
    verify_contract(GOOD_TOKEN_ADDRESS)
    if(get_owner(GOOD_TOKEN_ADDRESS) == get_creator(GOOD_TOKEN_ADDRESS)):
        print("⚠️ Current owner is the creator of the contract - ownership not renounced\n")
    else:
        print("✅ Current owner is NOT the creator of the contract - ownership not renounced\n")

    #HOLDER ANALYSIS
    #owner/creator wallet contains less than 5% of circulating token supply?
    #All other holders possess less than 5% of circulating token supply?
    print(f"🚀 Starting holder analysis for token: {GOOD_TOKEN_ADDRESS}")
    holders = holder_analysis(GOOD_TOKEN_ADDRESS)
    print(f"Total unique addresses holding the token: {len(holders)}")
    
    #Top 10 token holders possess less than 70% of circulating token supply?
    top10_analysis(GOOD_TOKEN_ADDRESS,holders)

    print("all done, bye!\n")
    return

if __name__ == '__main__':
    main()


"""
def holder_analysis():
    #%of locked tokens
    tokens_locked = 0

def liquidity_analysis():
    #adequate current liquidity? (low liquidity could potentially lead to high slippage)
    #at least 95% of liquidity burned/locked for at least 15 days?

"""