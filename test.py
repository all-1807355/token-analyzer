import requests
import time
from datetime import datetime
from moralis import evm_api
from urllib.parse import urlencode


ETHERSCAN_API_KEY = "YI5IUPU68CCB5AWVF8TP3T2BKY9FXW4QUH"
BSCSCAN_API_KEY = "IZJXB2H1EYWQ41PSSXC5HE4FMPS58KKPCZ"
MORALIS_API_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJub25jZSI6IjhmNjk4NzNlLTUzZjktNGUxNi05Yzk2LTViODM0OGQ3Y2RmMSIsIm9yZ0lkIjoiNDQzMjE0IiwidXNlcklkIjoiNDU2MDA5IiwidHlwZUlkIjoiZDc3NTRlMTctYWNhZi00NWU1LWJlMjEtZDQ0MjM4ZGMxZDZhIiwidHlwZSI6IlBST0pFQ1QiLCJpYXQiOjE3NDUzMTI1ODEsImV4cCI6NDkwMTA3MjU4MX0.TjBrdK-dzF9t5nRmQImzIenGGYussYsaqzKr7E_oXsc"

GOOD_TOKEN_ADDRESS = "0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82"
TOKEN_CONTRACT_ADDRESS = "0x30F07262961050662d107CFaBD717a7BdCc769d2"

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
    """
    Is the contract verified? -> get the ABI
    if yes, get the contract creator and the creation tx hash
    """
    print("starting contract verification")
    
    #Verify contract
    if(not verify_contract(token_address)):
        print("error!")
        return
    print("contract is verified, continue...")
    
    #Get creation transaction hash
    tx_hash = get_contract_creation_tx(token_address)
    if(tx_hash == None):
        print("error while getting tx hash")
        return
    blocknum = get_transaction_from_hash(tx_hash)
    result = get_timestamp_from_blocknum(blocknum)
    print(blocknum)
    print(result)
    creation_timestamp = datetime.fromtimestamp(int(result, 16))
    current_timestamp = datetime.now()

    #Compute token age
    age_seconds = (current_timestamp - creation_timestamp).total_seconds()
    print(creation_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
    print(current_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
    age_days = age_seconds // 86400
    age_hours = (age_seconds % 86400) // 3600
    age_minutes = (age_seconds % 3600) // 60
    print(f"Token age: {age_days} days, {age_hours} hours, {age_minutes} minutes")
    return

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

def get_unique_token_holders(token):
    page = 1
    addresses = set()

    # Keep paginating until no more results
    #while True:
    transactions = token_holders(token, page)
    #if transactions['status'] == '0' or not transactions['result']:
     #   break
    # Add both 'from' and 'to' addresses to the set
    for tx in transactions["result"]:
        addresses.add(tx["from"])
        addresses.add(tx["to"])

        #page += 1

    holders = [address for address in addresses if get_token_balance(GOOD_TOKEN_ADDRESS,address) > 0]
    return holders

def main():
    holders = get_unique_token_holders(GOOD_TOKEN_ADDRESS)
    print(f"Total unique addresses holding the token: {len(holders)}")
    return
    print("starting")
    get_token_age(GOOD_TOKEN_ADDRESS)
    print("all done, bye!\n")
    return

if __name__ == '__main__':
    main()


"""
TOKENSNIFFER ANALYSIS
def swap_analysis():
    #from honeypot.is

def contract_analysis():
    #is the contract source verified?
    try:
        verify_contract()
    except:
        print("The contract could not be verified")
    #does the source code contain a function which can modify the transaction fee?

    #Was the ownership of the contract renounced? If not, owner can change the behaviour of the contract.

def holder_analysis():
    #%of locked tokens
    tokens_locked = 0
    #owner/creator wallet contains less than 5% of circulating token supply?
    #All other holders possess less than 5% of circulating token supply?
    #Top 10 token holders possess less than 70% of circulating token supply?

def liquidity_analysis():
    #adequate current liquidity? (low liquidity could potentially lead to high slippage)
    #at least 95% of liquidity burned/locked for at least 15 days?

"""