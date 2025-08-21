import config

"""----------------------------------------"""
#HELPER FUNCTIONS
def debug_print(*args, **kwargs):
    """
    Print only if global DEBUG flag is set to True
    """
    if config.DEBUG:
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
        params['apikey'] = config.BSCSCAN_API_KEY
        base = config.BASE_URL_BSC
    elif chain == 'eth':
        params['apikey'] = config.ETHERSCAN_API_KEY
        base = config.BASE_URL_ETH
    url = f"{base}?{config.urlencode(params)}"
    try:
        res = config.requests.get(url)#, timeout=10)
        res.raise_for_status()
        return res.json()
    except (config.requests.RequestException, ValueError) as e:
        print(f"API call error: {e}")
        return None


"""----------------------------------------"""

def get_token_name(token_address: str, chain: str) -> str:
    config.scan_rate_limiter.acquire()
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
            name = config.Web3.to_text(raw[64:]).rstrip('\x00')
            #name = bytearray.fromhex(result[2:]).decode(errors='ignore').rstrip('\x00')
            return name
        except Exception:
            return "[Invalid name()]"
    
    # Fallback if function doesn't exist
    return "[name() not implemented]"

def get_contract_info(contract_address: str, chain: str) -> dict:
    config.scan_rate_limiter.acquire()
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
        info = {
            "source_code": None,
            "contract_name": None,
            "compiler_version": None,
            "license_type": None,
            "verified": None,
            "is_proxy": None,
            "implementation": None,
            "abi": None
        }
        return info

    result = res['result'][0]
    abi = result.get('ABI', '')
    is_verified = abi != 'Contract source code not verified'

    if not is_verified:
        debug_print(f"❌ Contract at {contract_address} is not verified.")
        info = {
            "source_code": None,
            "contract_name": None,
            "compiler_version": None,
            "license_type": None,
            "verified": False,
            "is_proxy": None,
            "implementation": None,
            "abi": None
        }
        return info

    # Extract data
    source_code = result.get('SourceCode', '')
    contract_name = result.get('ContractName', '')
    compiler_version = result.get('CompilerVersion', '')
    license_type = result.get('LicenseType', '')
    is_proxy = result.get('Proxy', '0') == '1'
    implementation_address = result.get('Implementation', '')

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
    config.scan_rate_limiter.acquire()
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
    config.scan_rate_limiter.acquire()
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
    if res.get('status') == '1' and res.get('result'):
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
                    trade_timestamp = config.datetime.fromtimestamp(int(item['timeStamp']))
                    creation_timestamp_dt = config.datetime.fromtimestamp(int(creation_timestamp))
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
        return {
                "creation_date": None,
                "time_delay_seconds": None,
                "block_delay": None
            }


def get_transaction_from_hash(hash: str, chain: str):
    config.scan_rate_limiter.acquire()
    params = {
        'module': 'proxy',
        'action': 'eth_getTransactionByHash',
        'txhash': hash,
    }
    res = api_call(params,chain)
    return res['result']['blockNumber'] if res['result'] else None

def get_latest_account_tx(address: str, chain: str):
    #TRANSFERS INVOLVING THE ADDRESS
    config.scan_rate_limiter.acquire()
    params = {
        "module": "account",
        "action": "tokentx",
        "address": address,
        "page": 1,
        "offset": 1,
        "sort": "desc",
    }
    res = api_call(params,chain)
    txs = res.get("result", [])
    return txs[0] if txs else None

def get_latest_tx(token: str, chain: str):
    #TRANSFERS INVOLVING ONLY THE TOKEN
    config.scan_rate_limiter.acquire()
    params = {
        "module": "account",
        "action": "tokentx",
        "contractaddress": token,
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
    config.scan_rate_limiter.acquire()
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
        if log["topics"][0].lower() == config.TRANSFER_TOPIC:
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
    config.scan_rate_limiter.acquire()
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
        return None
    blocknum = get_transaction_from_hash(tx_hash,chain)
    result = get_timestamp_from_blocknum(blocknum,chain)
    creation_timestamp = config.datetime.fromtimestamp(int(result,16))
    current_timestamp = config.datetime.now()

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
    config.scan_rate_limiter.acquire()
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
        last_time = config.datetime.fromtimestamp(timestamp)
        now = config.datetime.now()
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
        return {
            'last_tx_hash': None,
            'last_active_utc': None,
            'inactive_days': None
        }


def get_token_balance_API(token,account,chain):
    config.scan_rate_limiter.acquire()
    params = {
        'module': 'account',
        'action': 'tokenbalance',
        'contractaddress': token,
        'address': account,
        'tag': 'latest',
    }
    res = api_call(params,chain)
    return int(res['result']) if res['result'] else None

def get_token_balance_web3(address: str, token: str, web3: config.Web3, abi: list) -> int:
    """
    Retrieves the balance of `address` for an ERC-20 `token` using `web3.py`.
    """
    if abi == None:
        abi = [
            {
                "constant": True,
                "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf",
                "outputs": [{"name": "balance", "type": "uint256"}],
                "type": "function",
            }
        ]

    try:
        contract = web3.eth.contract(address=config.Web3.to_checksum_address(token), abi=abi)
        balance = contract.functions.balanceOf(config.Web3.to_checksum_address(address)).call()
        return balance
    except Exception as e:
        print(f"⚠️ Error fetching balance for {address}: {e}")
        return 0



def get_latest_block(chain):
    config.scan_rate_limiter.acquire()
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
    config.scan_rate_limiter.acquire()
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

    if startblock is None or endblock is None:
        print(f"Could not determine block range for address: {address}")
        return []

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

def get_holder_age(token, chain, address,max_pages=10,page_size=100):
    config.scan_rate_limiter.acquire()
    creation = get_contract_creation_tx(token, chain)
    creation_block = int(creation["blocknum"])
    last_block = int(get_latest_tx(token,chain)['blockNumber'])
    if not creation_block and not last_block:
        creation_block = 0
        last_block = 'latest'
    page = 1

    while page <= max_pages:
        params = {
            "module": "account",
            "action": "tokentx",
            "address": address,
            "startblock": creation_block,
            "endblock": last_block,
            "page": page,
            "offset": page_size,
            "sort": "asc",
        }

        try:
            res = api_call(params, chain)

            if res.get("status") == "1" and res.get("result"):
                token_txs = [
                    tx for tx in res["result"]
                    if tx.get("contractAddress", "").lower() == token.lower()
                    and tx.get("to", "").lower() == address.lower()
                ]

                if token_txs:
                    first_tx = token_txs[0]
                    earliest_time = int(first_tx["timeStamp"])
                    debug_print(f"Earliest received {token} tx for {address}: {config.datetime.fromtimestamp(earliest_time)}")
                    age = int(config.time.time()) - earliest_time
                    return {
                        "holder_age": age,
                        "holder_age_readable": str(config.timedelta(seconds=age))
                    }

                page += 1  # Go to next page
                config.scan_rate_limiter.acquire()

            else:
                debug_print(f"No more token transactions for {address} on page {page}")
                break

        except Exception as e:
            debug_print(f"Error fetching token transactions on page {page} for {address}: {e}")
            break

    return {
        "earliest_tx": None,
        "holder_age": None
    }



def get_unique_token_holders_web3(token_address: str, chain: str, web3: config.Web3, abi: list,
                          from_block: int, to_block: int = 'latest',
                          step: int = 5000, max_workers: int = 10) -> dict:
    holders = {}
    token_address = config.Web3.to_checksum_address(token_address)
    
    if isinstance(to_block, str) and to_block.lower() == 'latest':
        to_block = web3.eth.block_number
    all_addresses = set()

    print(f"📦 Scanning Transfer logs from block {from_block} to {to_block}...")
    for start in config.tqdm(range(from_block, to_block + 1, step)):
        end = min(start + step - 1, to_block)
        try:
            logs = web3.eth.get_logs({
                "fromBlock": start,
                "toBlock": end,
                "address": token_address,
                "topics": [config.TRANSFER_TOPIC]
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
        config.time.sleep(1)

    print(f"🔍 Found {len(all_addresses)} unique addresses. Checking balances...")

    

    # def check_balance(addr):
    #     try:
    #         balance = get_token_balance_API(token_address,addr,chain)
    #         # balance = balance_of(config.Web3.to_checksum_address(addr)).call()
    #         return (addr, balance) if balance > 0 else None
    #     except:
    #         return None
    contract = web3.eth.contract(address=config.Web3.to_checksum_address(token_address), abi=abi)
    try:
        balance_of = contract.functions.balanceOf
        use_api = False
    except AttributeError:
        balance_of = None
        use_api = True
    
    if use_api:
    # Use API to get balances
        with config.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(get_token_balance_API, token_address,addr,chain): addr for addr in all_addresses}
            for future in config.tqdm(config.as_completed(futures), total=len(futures)):
                result = future.result()
                if result:
                    addr, balance = result
                    holders[addr] = balance
    else:
        # Use on-chain balanceOf function
        with config.ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(balance_of(config.Web3.to_checksum_address(addr).lower()).call): addr for addr in all_addresses}
            for future in config.tqdm(config.as_completed(futures), total=len(futures)):
                addr = futures[future]
                try:
                    balance = future.result()
                    if balance:
                        holders[addr] = balance
                except Exception as e:
                    print(f"Error fetching balance for {addr}: {e}")
                    return {}

    print(f"✅ Found {len(holders)} holders with non-zero balances.")
    return holders

def get_unique_token_holders_API(token, chain, max_addresses=200):
    addresses = set()
    transactions = get_token_transfers(token, chain)
    if not transactions:
        return {}

    for tx in config.tqdm(transactions, desc="Processing transactions"):
        from_addr = tx["from"].lower()
        to_addr = tx["to"].lower()
        zero_addr = "0x0000000000000000000000000000000000000000"

        if from_addr != zero_addr:
            addresses.add(from_addr)
            if len(addresses) >= max_addresses:
                break
        if len(addresses) >= max_addresses:
            break
        if to_addr != zero_addr:
            addresses.add(to_addr)
            if len(addresses) >= max_addresses:
                break
    
    debug_print(f"Number of holders (limited to {max_addresses}): {len(addresses)}\n")

    # if chain == 'bsc':
    #     web3 = config.Web3(config.Web3.HTTPProvider(config.RPC_BSC))
    # elif chain == 'eth':
    #     web3 = config.Web3(config.Web3.HTTPProvider(config.RPC_ETH))
    holders = {}
    for addr in config.tqdm(addresses, desc="Fetching balances"):
        balance = get_token_balance_API(token, addr, chain)
        if balance is not None and balance > 0:
            holders[addr] = balance
        config.time.sleep(0.7)

    print(f"✅ Found {len(holders)} holders with non-zero balances.")
    return holders

def get_unique_token_holders_moralis(token, chain, max_pages=2, delay_seconds=1):
    params = {
        "chain": chain,
        "order": "DESC",
        "token_address": token
    }
    all_owners = []
    cursor = None
    pages_fetched = 0

    while True:
        if cursor:
            params["cursor"] = cursor
        else:
            params.pop("cursor", None)

        try:
            response = config.evm_api.token.get_token_owners(api_key=config.MORALIS_API_KEY, params=params)
        except Exception as e:
            error_message = str(e)
            if "free-plan-daily total included usage has been consumed" in error_message:
                print("API quota exceeded. Returning None.")
                return None
            print(f"API request failed: {e}")
            return None

        res = response.get("result", [])
        all_owners.extend(res)

        cursor = response.get("cursor")
        pages_fetched += 1
        if not cursor:
            break

        if max_pages and pages_fetched >= max_pages:
            print(f"Max pages limit reached: {max_pages}")
            break

        config.time.sleep(delay_seconds)  # simple rate limiter

    return {
        entry['owner_address'].lower(): int(float(entry['balance']))
        for entry in all_owners
        if int(float(entry['balance'])) > 0
    }


def is_hardcoded_owner(token,chain,info):
    privileged_keywords = ["owner", "admin", "dev", "fee", "wallet"]
    pattern = r'address\s+(?:public|private|internal)?\s*([a-zA-Z0-9_]+)\s*=\s*(0x[a-fA-F0-9]{40})'
    matches = config.re.findall(pattern, info,config.re.IGNORECASE)
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
    config.scan_rate_limiter.acquire()
    functionnames = ["owner","getowner","getOwner","admin"]
    for function in functionnames:
        func = '0x' + config.keccak(text=function + '()').hex()[:8]
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
    config.scan_rate_limiter.acquire()
    params = {
        'module': 'contract',
        'action': 'getcontractcreation',
        'contractaddresses': token,
    }
    res = api_call(params,chain)
    debug_print(f"The contract creator is {res['result'][0]['contractCreator'].lower()}\n")
    return res['result'][0]['contractCreator'] if res['status']=='1' else None

def get_total_supply(token,chain):
    config.scan_rate_limiter.acquire()
    params = {
        'module': 'stats',
        'action': 'tokensupply',
        'contractaddress': token,
    }
    res = api_call(params,chain)
    return int(res['result']) if res['result'] else None

def owner_circulating_supply_analysis(token,chain,owner,total_c_supply,web3: config.Web3,abi):
    debug_print(f"Owner/creator address: {owner}")
    owner_balance = get_token_balance_web3(owner, token, web3,abi)
    owner_percentage = (owner_balance / total_c_supply) * 100 if total_c_supply else 0.0

    owner_flag = owner_percentage > 5

    return owner_percentage,owner_flag

def holder_circulating_supply_analysis(holders,total_c_supply):
    """
    returns
    Owner/creator wallet contains < 5% of circulating token supply
    All other holders possess < 5% of circulating token supply
    Top 10 token holders possess < 70% of circulating token supply
    """
    #total_c_supply = get_circulating_supply(get_coingecko_id_from_contract(token, chain))
    #total_c_supply = get_circulating_supply_estimate(token,chain,holders)
    #if owner != creator:
    #    debug_print("owner is not the original creator\nowner: {owner}\ncreator:{creator}")
    #return
    #holders = get_unique_token_holders_moralis(token,chain)
    #holders = get_token_holders_moralis(token)
    debug_print(f"Analyzing {len(holders)} unique holders...")
    flagged_holders = []
    if holders == None:
        result = {
            'flagged_holders': None,
            'summary': {
                'total_holders_checked': 0,
                'holders_exceeding_5_percent': 0,
                'compliant': False
            }
        }
        return result
    
    for holder, balance in holders.items():
        # if holder == owner or holder == creator: continue
        percentage = balance / total_c_supply * 100 if total_c_supply else 0.0
        # Add individual holder details only if they exceed threshold
        if percentage > 5:
            flagged_holders.append({
                'address': holder,
                'balance': balance,
                'percentage_of_supply': percentage
            })

    result = {
        'flagged_holders': flagged_holders,
        'summary': {
            'total_holders_checked': len(holders),
            'holders_exceeding_5_percent': len(flagged_holders),
            'compliant': len(flagged_holders) == 0
        }
    }

    return result

def top10_analysis(holders: dict, total_supply,total_circulating):
    """
    Returns a dictionary with:
    - top_10 holders (address, balance, percentage of supply)
    - percentage of circulating supply held by top 10
    - compliance flag for <70% rule
    """
    #total_circulating = get_circulating_supply(get_coingecko_id_from_contract(token, chain))
    #total_circulating = get_circulating_supply_estimate(token,chain,holders)
    #total_supply = get_total_supply(token,chain)

    if holders == None:
        result = {
            'top_10_holders': None,
            'totals': {
                'total_top_10_balance': None,
                'total_top_10_percentage_of_total_supply': None,
                'total_top_10_percentage_of_circulating_supply': None,
                'top_10_less_than_70_percent_total_supply': None,
                'top_10_less_than_70_percent_circulating': None
            }
        }
        return result

    # Sort holders by balance
    sorted_holders = sorted(holders.items(), key=lambda x: x[1], reverse=True)
    top_10 = sorted_holders[:10]

    top_10_data = []
    total_top_10_balance = 0

    for addr, balance in top_10:
        percentage_circ = (balance / total_circulating) * 100 if total_circulating else 0
        percentage_tot = (balance / total_supply) * 100 if total_supply else 0
        top_10_data.append({
            'address': addr,
            'balance': balance,
            'percentage_of_total_supply': percentage_tot,
            'percentage_of_circulating_supply': percentage_circ
        })
        total_top_10_balance += balance

    percentage_circ_supply_total = (total_top_10_balance / total_circulating) * 100 if total_circulating else 0
    percentage_tot_supply_total = (total_top_10_balance / total_supply) * 100 if total_supply else 0

    result = {
        'top_10_holders': top_10_data,
        'totals': {
            'total_top_10_balance': total_top_10_balance,
            'total_top_10_percentage_of_total_supply': percentage_tot_supply_total,
            'total_top_10_percentage_of_circulating_supply': percentage_circ_supply_total,
            'top_10_less_than_70_percent_total_supply': percentage_tot_supply_total < 70,
            'top_10_less_than_70_percent_circulating': percentage_circ_supply_total < 70
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
    config.scan_rate_limiter.acquire()
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
    config.scan_rate_limiter.acquire()
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


def get_lp_pair(token: str, chain: str,web3) -> str:
    """
    Returns the LP pair address for a token-base_token pair on the given chain.
    """
    chain = chain.lower()
    if chain == "bsc":
        # RPC_URL = config.RPC_BSC
        factory_addr = config.Web3.to_checksum_address("0xca143ce32fe78f1f7019d7d551a6402fc5350c73")  # PancakeSwap V2
        base_pair_token = config.Web3.to_checksum_address("0xBB4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")  # WBNB
    elif chain == "eth":
        # RPC_URL = config.RPC_ETH  # Replace with actual Infura/Alchemy URL
        factory_addr = config.Web3.to_checksum_address("0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f")  # Uniswap V2
        base_pair_token = config.Web3.to_checksum_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")  # WETH
    else:
        raise ValueError("Unsupported chain. Use 'bsc' or 'ethereum'.")
    
    # web3 = config.Web3(config.Web3.HTTPProvider(RPC_URL))
    # if not web3.is_connected():
    #     raise ConnectionError(f"❌ Failed to connect to {chain} RPC.")

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

    token_address = config.Web3.to_checksum_address(token)
    base_token_address = config.Web3.to_checksum_address(base_pair_token)
    pair_address = factory.functions.getPair(token_address, base_token_address).call()
    return pair_address,pair_abi

def get_lp_holders(lp_address: str, web3: config.Web3, pair_abi: list,
                   from_block: int, to_block: int = 'latest',
                   step: int = 5000, max_holders: int = 30,
                   min_step: int = 1000) -> dict:
    """
    Efficiently gets LP holders with non-zero balances by scanning Transfer events in reverse.
    Only adds an address to the result if it has a positive balance.
    Stops early once `max_holders` are found.
    """
    TRANSFER_TOPIC = "0x" + config.Web3.keccak(text="Transfer(address,address,uint256)").hex()
    lp_address = config.Web3.to_checksum_address(lp_address)

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
                        from_addr = config.Web3.to_checksum_address("0x" + log["topics"][1].hex()[-40:])
                        to_addr = config.Web3.to_checksum_address("0x" + log["topics"][2].hex()[-40:])

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

def analyze_lp_security(token: str, chain: str = 'bsc') -> config.Dict:
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
    response = config.Token(access_token=None).token_security(chain_id=chain_id, addresses=[token])
    data = response.to_dict()

    # Safely extract token data
    result = data.get("result")
    if not isinstance(result, dict) or not result:
        print("❌ 'result' is missing or invalid in API response.")
        return {}

    token_data = next(iter(result.values()), None)
    if not isinstance(token_data, dict):
        print("❌ Token data not found or is malformed.")
        return {}

    # Safe fallback values
    lp_holders = token_data.get("lp_holders") or []
    lp_total_supply_raw = token_data.get("lp_total_supply")
    try:
        lp_total_supply = float(lp_total_supply_raw) if lp_total_supply_raw else 0.0
    except Exception as e:
        print(f"⚠️ Failed to parse lp_total_supply: {e}")
        lp_total_supply = 0.0

    # Calculate % of LP locked
    locked_amount = 0.0
    for holder in lp_holders:
        try:
            if holder.get("is_locked"):
                locked_amount += float(holder.get("balance") or 0.0)
        except Exception as e:
            print(f"⚠️ Failed to parse holder balance: {e}")

    percent_locked = (locked_amount / lp_total_supply) * 100 if lp_total_supply else 0.0

    # Check if ≥95% locked for ≥15 days
    now = config.datetime.now()
    long_term_locked = 0.0

    for holder in lp_holders:
        for lock in holder.get("locked_detail") or []:
            end_time_str = lock.get("end_time")
            if not end_time_str:
                continue
            try:
                end_time = config.datetime.fromisoformat(end_time_str.replace("Z", "+00:00"))
                if (end_time - now).days >= 15:
                    long_term_locked += float(lock.get("amount") or 0.0)
            except Exception as e:
                print(f"⚠️ Failed parsing lock detail: {e}")

    locked_95_for_15d = (long_term_locked / lp_total_supply) * 100 >= 95 if lp_total_supply else False

    # Creator / Owner info
    try:
        creator_percent_of_lp = float(token_data.get("creator_percent") or 0.0) * 100
    except Exception:
        creator_percent_of_lp = 0.0
    creator_under_5_percent = creator_percent_of_lp < 5

    try:
        owner_percent_of_lp = float(token_data.get("owner_percent") or 0.0) * 100
    except Exception:
        owner_percent_of_lp = 0.0
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
                "address": holder.get("address"),
                "balance": float(holder.get("balance") or 0.0),
                "is_locked": bool(holder.get("is_locked")),
                "percent": float(holder.get("percent") or 0.0),
                "tag": holder.get("tag") or ""
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

def compute_locked_lp_percentage(lockers: dict, lp_address: str, web3: config.Web3, pair_abi: list) -> float:
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

def compute_95pct_locked_or_burned(token_address: str,web3: config.Web3,pair_abi: list,chain: str,from_block: int,to_block: int = "latest") -> float:
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
    unlock_time = config.datetime.utc_from_timestamp(unlock_timestamp)
    return unlock_time > config.datetime.now() + config.datetime.timedelta(days=15)

def get_unlock_timestamp(locker_address: str, lp_token_address: str, chain: str, web3: config.Web3) -> int:
    """
    Dynamically infers the unlock timestamp of LP tokens locked in a contract.
    It does this by analyzing the contract's ABI and probing known unlock method names.
    """
    locker_address = config.Web3.to_checksum_address(locker_address)

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
            if unlock_time > int(config.time.time()):
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
        selector_to_method = config.json.load(f)  # dict: e.g. { "0xa9059cbb": "transfer(address,uint256)" }

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

def find_latest_tx_block(address, chain):
    config.scan_rate_limiter.acquire()
    """Get the latest transaction block by scanning backward."""
    latest_block = None
    step = 50000
    high = get_latest_block(chain)

    with config.tqdm(desc="Searching for latest tx block") as pbar:
        while high >= 0:
            params = {
                "module": "account",
                "action": "txlist",
                "address": address,
                "startblock": max(0, high - step),
                "endblock": high,
                "sort": "desc",
            }
            res = api_call(params, chain)
            if res.get("status") == "1" and res["result"]:
                latest_block = int(res["result"][0]["blockNumber"])
                break
            high -= step

    return latest_block

def isburner(address,chain,creation_blocknum,last_block):
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
    return False

    #NOTE Always better to look among the transactions.

    # creation = get_contract_creation_tx(address,chain)
    # #SKIP IF YOU CAN'T GET CREATION TX -> insufficient data 
    # if not creation:
    #     return False
    # creation_timestamp = creation["timestamp"]
    # creation_blocknum = int(creation["blocknum"])
    # last_block = int(get_latest_tx(address,chain)['blockNumber'])

    txs = get_tx_list(address,creation_blocknum,last_block,chain)
    if txs:
        for tx in txs:
            if tx.get("from", "").lower() == address:
                return False  # ❌ Has sent a transaction

    token_txs = get_account_token_transfers(address, chain)
    for tx in token_txs:
        if tx.get("from", "").lower() == address:
            return False  # ❌ Has sent tokens

    return True

def get_token_transfers(token,chain):
    config.scan_rate_limiter.acquire()
    creation = get_contract_creation_tx(token,chain)
    creation_blocknum = int(creation["blocknum"]) 
    last_block = int(get_latest_tx(token,chain)['blockNumber'])

    params = {
        'module': 'account',
        'action': 'tokentx',
        'contractaddress': token,
        'startblock': creation_blocknum,
        'endblock': last_block,
        'sort': 'asc',
    }

    res = api_call(params,chain)
    return res["result"] if res and "result" in res else None#['result'] if res['result'] else None

def get_first_account_tx(address: str, chain: str) -> dict:
    config.scan_rate_limiter.acquire()
    """
    Retrieves the first transaction involving the given address.

    Args:
        address (str): The wallet or contract address.
        chain (str): Blockchain to use ('eth', 'bsc', etc.)

    Returns:
        dict or None: First transaction's hash, timestamp, and block number.
    """
    params = {
        'module': 'account',
        'action': 'txlist',
        'address': address,
        'startblock': 0,
        'endblock': 99999999,
        'page': 1,
        'offset': 1,
        'sort': 'asc'  # Ascending = first tx appears first
    }

    res = api_call(params, chain)

    if res.get('status') == '1' and res.get('result'):
        tx = res['result'][0]
        return {
            'hash': tx['hash'],
            'timestamp': tx['timeStamp'],
            'blocknum': tx['blockNumber']
        }
    else:
        return None

def get_account_token_transfers(address,chain):
    config.scan_rate_limiter.acquire()
    tx = get_first_account_tx(address, chain) or get_contract_creation_tx(address, chain)
    if tx:
        creation_blocknum = tx['blocknum']
    else:
        creation_blocknum = 0
    last_block = int(get_latest_account_tx(address,chain)['blockNumber'])

    params = {
        'module': 'account',
        'action': 'tokentx',
        'address': address,
        'startblock': creation_blocknum,
        'endblock': last_block,
        'sort': 'asc',
    }

    res = api_call(params,chain)
    return res["result"] if res and "result" in res else []#['result'] if res['result'] else None


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

    pair_address,pair_abi = get_lp_pair(token,chain)

    # ------- HELPER FUNCTION -------
    def to_percent(numer, denom):
        return float(numer) / float(denom) * 100 if denom > 0 else 0

    if pair_address == "0x0000000000000000000000000000000000000000":
        print("❌ No liquidity pair found for token and base pair.")
        return

    print("✅ Found LP pair:", pair_address)
    if chain == 'eth':
        web3 = config.Web3(config.Web3.HTTPProvider(config.RPC_ETH))
    elif chain == 'bsc':
        web3 = config.Web3(config.Web3.HTTPProvider(config.RPC_BSC))
    pair = web3.eth.contract(address=pair_address, abi=pair_abi)
    total_lp = pair.functions.totalSupply().call()
    creator = config.Web3.to_checksum_address(get_creator(token, chain))
    creator_lp = pair.functions.balanceOf(creator).call()

    pct = to_percent(creator_lp, total_lp)
    print(f"\n📊 Creator owns {pct:.4f}% of LP tokens")

    if pct < 5:
        print("✅ Creator holds less than 5% of liquidity.")
    else:
        print("⚠️ Creator holds MORE than 5% of the liquidity — potential risk!")


"""----------------------------------------"""

def extract_all_functions(source_code: str):
    functions = []
    inside_function = False
    brace_count = 0
    current_function = []

    lines = source_code.splitlines()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("function"):
            inside_function = True
            brace_count = 0
            current_function = [line]
            brace_count += line.count("{") - line.count("}")
            continue
        elif inside_function:
            current_function.append(line)
            brace_count += line.count("{") - line.count("}")
            if brace_count <= 0:
                inside_function = False
                functions.append("\n".join(current_function))

    return functions


def analyze_token_contract_with_snippets(source_code: str, pbar=None) -> dict:
    findings = {}
    normalized_code = source_code.lower()
    funcs = extract_all_functions(normalized_code)
    keyword_categories = {
        'mint_function_detected': [
            'mint', 'minttoken', 'minted', 'mining', 'claim', 'reward', 'gift', 'bonus', 'earn', 'airdrop', 'unlock',
            'tokenclaim', 'tokendrop', 'mintnft', 'airdropnft', 'claimnft', 'promoclaim', 'promotionbonus',
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

    progress_step = 1 / len(keyword_categories) if pbar else None

    for category, keywords in keyword_categories.items():
        matching_funcs = [func for func in funcs if any(keyword.lower() in func.lower() for keyword in keywords)]
        findings[category] = {
            'found': bool(matching_funcs),
            'snippets': matching_funcs,
            'snippets_number': len(matching_funcs)
        }
        if pbar:
            pbar.update(progress_step)
    return findings


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
    res = config.requests.get(url)
    if res.status_code != 200:
        print(f"CoinGecko ID lookup failed: {res.status_code}")
        return None
    return res.json().get('id')

def get_circulating_supply(coingecko_id):
    url = f"https://api.coingecko.com/api/v3/coins/{coingecko_id}"
    res = config.requests.get(url)
    if res.status_code != 200:
        return None
    try:
        return float(res.json()['market_data']['circulating_supply'])
    except (KeyError, TypeError, ValueError):
        return None

def get_circulating_supply_estimate(token,chain,total_supply,addresses = ''):
    if addresses == '' or addresses == None:
        return total_supply #NOTE skip if you can't get holders
        holders = get_unique_token_holders_moralis(token,chain)
    else:
        holders = addresses
    c_supply = 0
    locked_or_burned_supply = 0
    #NOTE REMOVED FOR TESTING
    # tx = get_first_account_tx(token, chain) or get_contract_creation_tx(token, chain)
    # if tx:
    #     creation_blocknum = tx['blocknum']
    # else:
    #     creation_blocknum = 0
    # last_block = find_latest_tx_block(token,chain)
    # if not last_block:
    #     last_block = 'latest'

    for holder,balance in config.tqdm(holders.items(), desc="Calculating Circulating Supply", unit="address"):
        #NOTE values set to 0 for testing
        if islocker(holder,chain) or isburner(holder,chain,creation_blocknum = 0,last_block = 0):
            locked_or_burned_supply += balance
        else:
            c_supply += balance
    # print(f"c_supply: {c_supply}")
    # print(f"total_supply: {total_supply}")
    # print(f"locked_or_burned_supply: {locked_or_burned_supply}")
    return (c_supply + total_supply - locked_or_burned_supply) // 2

def get_dexscreener_price_liquidity_volume(token_address,chainId = 1):
    # url = f'https://api.dexscreener.com/token-pairs/v1/{chainId}/{token_address}'
    if chainId == 1:
        chain = 'ethereum'
    elif chainId == 56:
        chain = 'btc'
    url = f"https://api.dexscreener.com/latest/dex/tokens/{token_address}"
    res = config.requests.get(url).json()
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


def get_quote_token_usd_price(token_address: str,chain: str, web3) -> float:
    # Stablecoin assumed = 1 USD
    for stable_addr in config.STABLECOINS[chain].values():
        if token_address.lower() == stable_addr.lower():
            return 1.0

    # Use reference pair to calculate price in USD
    if chain == "eth":
        ref = config.REFERENCE_PAIRS["eth"]["weth_usdc"]
    elif chain == "bsc":
        ref = config.REFERENCE_PAIRS["bsc"]["wbnb_busd"]
    else:
        raise ValueError("Unsupported chain for reference pricing.")

    ref_pair = web3.eth.contract(address=config.Web3.to_checksum_address(ref["pair"]), abi=config.PAIR_ABI)
    reserves = ref_pair.functions.getReserves().call()

    if token_address.lower() == ref["token0"].lower():
        token_reserve = reserves[0] / (10 ** ref["token0_decimals"])
        usd_reserve = reserves[1] / (10 ** ref["token1_decimals"])
    elif token_address.lower() == ref["token1"].lower():
        token_reserve = reserves[1] / (10 ** ref["token1_decimals"])
        usd_reserve = reserves[0] / (10 ** ref["token0_decimals"])
    else:
        raise ValueError("Token not found in reference pair.")

    return usd_reserve / token_reserve if token_reserve > 0 else 0

def get_price_and_liquidity(pair_address: str, base_token_address: str, chain: str, web3, base_decimals=18, quote_decimals=18):
    try:
        if chain not in ['bsc', 'eth']:
            raise ValueError("Unsupported chain")
        if chain == 'bsc':
            url = config.BASE_URL_BSC
        elif chain == 'eth':
            url = config.BASE_URL_ETH

        pair = web3.eth.contract(address=config.Web3.to_checksum_address(pair_address), abi=config.PAIR_ABI)
        reserves = pair.functions.getReserves().call()
        token0 = pair.functions.token0().call()
        token1 = pair.functions.token1().call()

        if token0.lower() == base_token_address.lower():
            base_reserve = reserves[0] / (10 ** base_decimals)
            quote_reserve = reserves[1] / (10 ** quote_decimals)
            quote_token = token1
        elif token1.lower() == base_token_address.lower():
            base_reserve = reserves[1] / (10 ** base_decimals)
            quote_reserve = reserves[0] / (10 ** quote_decimals)
            quote_token = token0
        else:
            raise ValueError("Base token not in this pair")

        quote_token_usd_price = get_quote_token_usd_price(quote_token, chain, web3)
        price_usd = (quote_reserve / base_reserve) * quote_token_usd_price if base_reserve > 0 else 0
        liquidity_usd = (base_reserve * price_usd) + (quote_reserve * quote_token_usd_price)

        return {
            "price_usd": price_usd,
            "liquidity_usd": liquidity_usd,
            "base_token_reserve": base_reserve,
            "quote_token_reserve": quote_reserve,
            "quote_token_usd_price": quote_token_usd_price
        }
    except Exception:
        # Silently catch any exception, return None-filled dict
        return None
        # return {
        #     "price_usd": None,
        #     "liquidity_usd": None,
        #     "base_token_reserve": None,
        #     "quote_token_reserve": None,
        #     "quote_token_usd_price": None
        # }

def get_liquidity_to_marketcap_ratio(circulating_supply, price, liquidity, verbose=False):
    # Step 1: Get CoinGecko ID
    # coingecko_id = get_coingecko_id_from_contract(token_address, chain)
    # supply = None

    # # Step 2: Try CoinGecko for circulating supply
    # if coingecko_id:
    #     supply = get_circulating_supply(coingecko_id)
    #     if verbose:
    #         print(f"CoinGecko ID: {coingecko_id}, Supply from CoinGecko: {supply}")
    # else:
    #     supply = get_circulating_supply_estimate(token_address,chain,holders)
    #     if verbose:
    #         print(f"CoinGecko ID not found, supply from estimate: {supply}")

    # if not supply:
    #     if verbose: print("Failed to get circulating supply from both sources.")
    #     return None

    # Step 3: Get price and liquidity from DEXScreener
    #price_liquidity = get_dexscreener_price_liquidity_volume(token_address)
    # if not price_liquidity:
    #     if verbose: print("Failed to get DEXScreener price or liquidity.")
    #     return None

    market_cap = circulating_supply * price
    ratio = liquidity / market_cap if market_cap else 0

    if verbose:
        print(f"Price: ${price}")
        print(f"Liquidity: ${liquidity}")
        print(f"Market Cap: ${market_cap}")
        print(f"Liquidity to Market Cap Ratio: {ratio:.4f}")

    return {
        'price_usd': price,
        'circulating_supply': circulating_supply,
        'market_cap_usd': market_cap,
        'liquidity_usd': liquidity,
        'liquidity_to_market_cap_ratio': ratio
    }



def get_volume_to_liquidity_ratio(web3: config.Web3, pair_address: str, latest_block: int, chain: str, token_price_usd: float, liquidity_usd: float):
    """
    Computes 24h volume-to-liquidity ratio for a UniswapV2-style LP pair.
    Assumes liquidity in USD is provided externally.
    Automatically detects the non-stable token for volume calculation.

    Args:
        web3 (Web3): Web3 instance.
        pair_address (str): LP contract address.
        latest_block (int): Latest block number.
        chain (str): 'eth', 'bsc', etc.
        token_price_usd (float): Price of the non-stable token in USD.
        liquidity_usd (float): Total liquidity in USD, externally provided.

    Returns:
        dict: Contains token_volume, volume_usd, and vol_liq_ratio.
    """
    pair_address = web3.to_checksum_address(pair_address)

    # Estimate 24h block range
    blocks_per_day = 28800 if chain == "bsc" else 6500
    from_block = max(latest_block - blocks_per_day, 0)

    # Swap event signature hash
    swap_event_sig = "0x" + web3.keccak(text="Swap(address,uint256,uint256,uint256,uint256,address)").hex()

    # Infura and others often limit log queries to ~1000-5000 blocks per request
    MAX_BLOCK_RANGE = 1000  # adjust if needed based on provider limits

    logs = []
    current_from = from_block

    MAX_RETRIES = 5
    RETRY_DELAY = 2  # seconds

    while current_from <= latest_block:
        current_to = min(current_from + MAX_BLOCK_RANGE - 1, latest_block)
        for attempt in range(MAX_RETRIES):
            try:
                chunk_logs = web3.eth.get_logs({
                    "fromBlock": current_from,
                    "toBlock": current_to,
                    "address": pair_address,
                    "topics": [swap_event_sig],
                })
                logs.extend(chunk_logs)
                break  # break retry loop on success
            except Exception as e:
                if "429" in str(e) and attempt < MAX_RETRIES - 1:
                    print(f"Rate limit hit. Retrying after {RETRY_DELAY} seconds...")
                    config.time.sleep(RETRY_DELAY * (attempt + 1))  # exponential backoff
                else:
                    print(f"Failed to fetch logs from {current_from} to {current_to}: {e}")
                    break
        current_from = current_to + 1
    
    # Load LP contract and get token addresses
    pair_abi = [
        {"name": "token0", "outputs": [{"type": "address"}], "inputs": [], "stateMutability": "view", "type": "function"},
        {"name": "token1", "outputs": [{"type": "address"}], "inputs": [], "stateMutability": "view", "type": "function"},
    ]
    pair_contract = web3.eth.contract(address=pair_address, abi=pair_abi)
    token0 = pair_contract.functions.token0().call().lower()
    token1 = pair_contract.functions.token1().call().lower()

    # Compose stable addresses list: stablecoins + wrapped native token for this chain
    stable_addrs = [addr.lower() for addr in config.STABLECOINS[chain].values()]

    wrapped_native_token = None
    if chain in config.REFERENCE_PAIRS:
        for ref_key, ref_val in config.REFERENCE_PAIRS[chain].items():
            wrapped_native_token = ref_val["token1"].lower()
            break

    if wrapped_native_token:
        stable_addrs.append(wrapped_native_token)

    # Determine which token is stable
    token0_is_stable = token0 in stable_addrs
    token1_is_stable = token1 in stable_addrs

    if token0_is_stable and token1_is_stable:
        raise ValueError("Both tokens in the pair are stablecoins or wrapped native tokens — nothing to analyze.")
    elif not token0_is_stable and not token1_is_stable:
        raise ValueError("Neither token is a recognized stablecoin or wrapped native token — cannot compute ratio.")

    # Identify non-stable token
    token_address = token1 if token0_is_stable else token0
    token_index = 1 if token0_is_stable else 0
    # Get token decimals
    erc20_abi = [{"name": "decimals", "outputs": [{"type": "uint8"}], "inputs": [], "stateMutability": "view", "type": "function"}]
    token_contract = web3.eth.contract(address=web3.to_checksum_address(token_address), abi=erc20_abi)
    decimals = token_contract.functions.decimals().call()

    # Sum Swap volume from logs
    total_token_volume = 0
    for log in logs:
        try:
            data = log["data"]
            decoded = config.decode_abi(["uint256", "uint256", "uint256", "uint256"], data)
            amount_in = decoded[token_index]
            amount_out = decoded[token_index + 2]
            total_token_volume += amount_in + amount_out
        except Exception:
            continue

    print(f"total_token_volume: {total_token_volume}")
    token_volume = total_token_volume / (10 ** decimals)
    volume_usd = token_volume * token_price_usd

    print(f"token_volume, volume_usd: {token_volume} {volume_usd}")
    if liquidity_usd == 0:
        return {
            'token_volume': token_volume,
            'volume_usd': volume_usd,
            'vol_liq_ratio': 0.0
        }

    return {
        'token_volume': token_volume,
        'volume_usd': volume_usd,
        'vol_liq_ratio': volume_usd / liquidity_usd
    }







# def get_volume_to_liquidity_ratio(price,liquidity, volume_24h, verbose=False):
#     #price_liquidity = get_dexscreener_price_liquidity_volume(token_address)
#     if not price or not liquidity:
#         if verbose:
#             print("Failed to get DEX data for token.")
#         return None

#     price, liquidity, volume_24h = price, liquidity, volume_24h
#     ratio = volume_24h / liquidity if liquidity else 0

#     if verbose:
#         print(f"24h Volume: ${volume_24h:,.2f}")
#         print(f"Liquidity: ${liquidity:,.2f}")
#         print(f"Volume/Liquidity Ratio: {ratio:.4f}")

#     return {
#         'price_usd': price,
#         'volume_usd_24h': volume_24h,
#         'liquidity_usd': liquidity,
#         'volume_to_liquidity_ratio': ratio
#     }
"""----------------------------------------"""

def run_security_checks(token, chain,source_code):
    """
    address darklist = A list of addresses that deserve to be accompanied by a warning.
    URL darklist = A list of URLs known to be fake, malicious, phishing.
    bsc-blacklist.json = list of bsc addresses known to be scams.
    ethereum-blacklist.json = list of eth addresses known to be scams.
    """
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

    with open("/home/amedeo/Desktop/code_tests/data/addresses-darklist.json") as f:
        address_blacklist = config.json.load(f)

    with open("/home/amedeo/Desktop/code_tests/data/urls-darklist.json") as f:
        url_blacklist = config.json.load(f)

    if chain == 'bsc':
        with open("/home/amedeo/Desktop/code_tests/data/bsc-blacklist.json") as f:
            scammers_blacklist = config.json.load(f)
    elif chain == 'eth':
        with open("/home/amedeo/Desktop/code_tests/data/ethereum-blacklist.json") as f:
            scammers_blacklist = config.json.load(f)
    
    lowtoken = token.lower()

    # Initialize the lists
    matching_warnings = []
    matching_urls = {}
    matching_addresses = {}

    # Address Blacklist Check
    for address in address_blacklist:
        if address["address"].lower() == lowtoken:
            matching_warnings.append({
                "address": address['address'],
                "comment": address['comment']
            })
            print(f"Address: {address['address']}")
            print(f"Comment: {address['comment']}")

    # URL Blacklist Check
    urls = config.re.findall(r'https?://[^\s"\'<>]+', source_code,config.re.IGNORECASE)
    for blacklisted in url_blacklist:
        for found_url in urls:
            if blacklisted["id"] == found_url:
                print("Found URL inside the contract (known to be fake, malicious or a phishing url):", found_url)
                print("   → URL:", found_url)
                print("   → Reason:", blacklisted["comment"])
            matching_urls[found_url] = blacklisted["comment"]
    
    # Token Address Check for Scammers Blacklist
    if token in scammers_blacklist["tokens"]:
        print("Token address matches a suspicious address in the database!: ", token)

    found_addresses = config.re.findall(r'0x[a-fA-F0-9]{40}', source_code,config.re.IGNORECASE)
    for address in found_addresses:
        if address in scammers_blacklist["tokens"]:
            print("Found a suspicious address in the source code match with the database: ", address)
            matching_addresses[token] = address  # Corrected line

    return {
        "warnings": matching_warnings,
        "suspicious_urls": matching_urls,
        "suspicious_addresses": matching_addresses
    }

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
    token_address = config.Web3.to_checksum_address(token_address)
    if chain == "bsc":
        rpc_url = config.RPC_BSC
        router_addr = config.Web3.to_checksum_address("0x10ED43C718714eb63d5aA57B78B54704E256024E")  # PancakeSwap
        base_pair_token = config.Web3.to_checksum_address("0xBB4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c")  # WBNB
    elif chain == "eth":
        rpc_url = config.RPC_ETH 
        router_addr = config.Web3.to_checksum_address("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D")  # Uniswap
        base_pair_token = config.Web3.to_checksum_address("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")  # WETH
    else:
        raise ValueError("Unsupported chain. Use 'bsc' or 'ethereum'.")
    
    w3 = config.Web3(config.Web3.HTTPProvider(rpc_url))

    ROUTER_ABI = config.json.loads(
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
            web3 = config.Web3(config.Web3.HTTPProvider(config.RPC_BSC))
        elif chain == 'eth':
            web3 = config.Web3(config.Web3.HTTPProvider(config.RPC_ETH))
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
    report_lines = []
    report_lines.append(f"Token Analysis Report\n{'='*50}\n")
    report_lines.append(f"Token: {results['token_name']} ({token_address})\n")
    report_lines.append(f"Chain: {chain.upper()}\n\n")

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
            
            report_lines.append("Contract Analysis\n-----------------\n")
            report_lines.append(f"Verified: {'OK!' if contract_info['verified'] else 'X'}\n")
            report_lines.append(f"Owner Address: {results['analyses']['contract']['owner']}\n")
            report_lines.append(f"Creator Address: {results['analyses']['contract']['creator']}\n")
            report_lines.append(f"Is Proxy: {'Yes' if contract_info['is_proxy'] else 'No'}\n")
            report_lines.append(f"Is sellable (no honeypot): {'Yes' if sellable else 'No'}\n")
            report_lines.append(f"Is owner hardcoded: {'Yes' if hardcoded else 'No'}\n")

            if contract_info['source_code']:
                analysis = analyze_token_contract_with_snippets(contract_info['source_code'])
                results['analyses']['contract']['code_analysis'] = analysis
                
                report_lines.append("\nCode Analysis Findings:\n")
                for category, data in analysis.items():
                    if data['found']:
                        report_lines.append(f"WARNING: {category.replace('_', ' ').title()}\n")
                        for snippet in data['snippets']:
                            report_lines.append(f"  Code Snippet:\n{snippet}\n\n")

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
    
        report_lines.append("\nHolder Analysis\n--------------\n")
        report_lines.append(f"Total Unique Holders: {len(holders)}\n")
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
            # age = get_holder_age(address,chain)  # You define this
            enriched_dict[address] = {
                "balance": balance,
                "age": None
            }

        results['analyses']['holders'] = {
            'total_holders': len(holders),
            'holders_list': enriched_dict,

            #'owner_percentage': f"{owner_percentage}\n" if owner_percentage else "0\n",  # Will be calculated if coingecko data is available
            'owner_is_hidden': False if owner else True,
        }
        
        coingecko_id = get_coingecko_id_from_contract(token_address, chain)
        if coingecko_id != None:
            total_c_supply = get_circulating_supply(coingecko_id)
        else:
            total_c_supply = get_circulating_supply_estimate(token_address,chain,holders)

        results.update({'total_circulating_supply': total_c_supply})
        results['analyses']['holders'].update(holder_circulating_supply_analysis(token_address,chain,holders,total_c_supply,web3,abi))
        results['analyses']['holders'].update(top10_analysis(token_address,chain,holders,total_c_supply))
        # Owner section
        if 'owner' in results['analyses']['holders']:
            report_lines.append(f"Owner Address: {results['analyses']['holders']['owner'].get('address', 'Unknown')}\n")
            report_lines.append(f"Owner Balance: {results['analyses']['holders']['owner'].get('balance', 0):,} tokens\n")
            report_lines.append(f"Owner Share: {results['analyses']['holders']['owner'].get('percentage_of_supply', 0):.2f}% of circulating supply\n")
            if results['analyses']['holders']['owner'].get('exceeds_5_percent', False):
                report_lines.append("⚠️ Owner holds MORE than 5% of circulating supply\n")
            else:
                report_lines.append("✅ Owner holds LESS than 5% of circulating supply\n")
        else:
            report_lines.append("⚠️ Owner information is not available (possibly hidden or unverified)\n")

        # Holder over 5% section
        if 'summary' in results['analyses']['holders']:
            total_checked = results['analyses']['holders']['summary'].get('total_holders_checked', 0)
            over_5 = results['analyses']['holders']['summary'].get('holders_exceeding_5_percent', 0)
            compliant = results['analyses']['holders']['summary'].get('compliant', False)

            report_lines.append(f"Holders Checked (excluding owner): {total_checked}\n")
            report_lines.append(f"Holders >5%: {over_5}\n")
            report_lines.append("✅ All holders under 5% threshold\n" if compliant else "⚠️ Some holders exceed 5% of supply\n")
        else:
            report_lines.append("⚠️ Holder analysis data is missing\n")

        # Top 10 holders section
        if 'top_10_holders' in results['analyses']['holders']:
            report_lines.append("\nTop 10 Token Holders:\n")
            for i, h in enumerate(results['analyses']['holders']['top_10_holders'], start=1):
                addr = h.get('address', 'Unknown')
                bal = h.get('balance', 0)
                pct = h.get('percentage_of_circulating_supply', 0)
                report_lines.append(f"  {i}. {addr} — {bal:,} tokens ({pct:.2f}% of circulating supply)\n")

            totals = results['analyses']['holders'].get('totals', {})
            circ_pct = totals.get('percentage_of_circulating_supply', 0)
            total_pct = totals.get('percentage_of_total_supply', 0)
            less_than_70 = totals.get('top_10_less_than_70_percent_circulating', True)

            report_lines.append(f"\nTop 10 Total Balance: {totals.get('total_top_10_balance', 0):,} tokens\n")
            report_lines.append(f"Top 10 Share of Circulating Supply: {circ_pct:.2f}%\n")
            report_lines.append(f"Top 10 Share of Total Supply: {total_pct:.2f}%\n")
            report_lines.append("✅ Top 10 holders control LESS than 70% of circulating supply\n" if less_than_70 else "⚠️ Top 10 holders control MORE than 70% of circulating supply\n")
        else:
            report_lines.append("⚠️ Top 10 holder analysis is not available\n")
            
    if 'liquidity' in analysis_types:
        print("\n🔍 Running liquidity analysis...")
        data = get_dexscreener_price_liquidity_volume(token_address)
        if not data:
            report_lines.append(f"⚠️ ERROR: no pair token data found!")
            pass
        price, liquidity_pool_depth, volume = data
        
        total_c_supply = results.get('total_circulating_supply','')
        if total_c_supply == '':
            coingecko_id = get_coingecko_id_from_contract(token_address, chain)
            if coingecko_id != None:
                total_c_supply = get_circulating_supply(coingecko_id)
            else:
                total_c_supply = get_circulating_supply_estimate(token_address,chain,holders)
        holders = results['analyses'].get('holders', {}).get('holder_list', get_unique_token_holders_moralis(token_address,chain))
        liq_market_ratio = get_liquidity_to_marketcap_ratio(token_address,chain,holders,total_c_supply,data)
        vol_liq_ratio = get_volume_to_liquidity_ratio(data)
        
        lp_address, web3, pair_abi = get_lp_pair(token_address,chain)
        creation = get_contract_creation_tx(token_address,'bsc')
        creation_timestamp = creation["timestamp"]
        creation_blocknum = int(creation["blocknum"])
        #liquidity_holders = get_lp_holders(lp_address, web3, pair_abi, from_block=creation_blocknum,to_block="latest")
        liquidity_status = analyze_lp_security(token_address,chain)
        liquidity_holders = liquidity_status["lp_holders"]

        lp_contract = web3.eth.contract(address=config.Web3.to_checksum_address(lp_address), abi=pair_abi)
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
        
        report_lines.append("\nLiquidity Analysis\n-----------------\n")
        if liq_market_ratio:
            report_lines.append(f"Market Cap: ${liq_market_ratio['market_cap_usd']:,.2f}\n")
            report_lines.append(f"Liquidity: ${liquidity_pool_depth:,.2f}\n")
            report_lines.append(f"Liquidity/MCap Ratio: {liq_market_ratio['liquidity_to_market_cap_ratio']:.4f}\n")
        if vol_liq_ratio:
            report_lines.append(f"24h Volume/Liquidity Ratio: {vol_liq_ratio['volume_to_liquidity_ratio']:.4f}\n")
        if liquidity_status:
            report_lines.append(f"Percentage of liquidity locked: {liquidity_status['locked_liquidity_percent']:.4f}\n")
            report_lines.append(f"Was 95% of liquidity locked for more than 15 days?: {liquidity_status['locked_95_for_15_days']}\n")
            report_lines.append(f"Secure\n" if {liquidity_status['locked_95_for_15_days']} else "Unverified or Unlocked\n")
            report_lines.append(f"Creator owns under 5% of LP tokens: {liquidity_status['creator_under_5_percent']} ({liquidity_status['creator_percent_of_lp']})\n")
            report_lines.append(f"Total supply of LP tokens: {liquidity_status['total_lp_supply']}\n")
            report_lines.append(f"LP holders count: {liquidity_status['lp_holders_count']}\n")
            report_lines.append(f"\r\n")
 
            report_lines.append(f"Liquidity holders for {token_address}, ({results["token_name"] if results["token_name"] else get_token_name(token_address,chain)})\n")
            for holder in liquidity_holders:
                if holder["address"] == owner:
                    report_lines.append(f"\r\nOwner {holder["address"]} holds {holder["balance"]} LP tokens\r\n")
                    owner_lp_balance = holder["balance"]
                    #check if owner holds less than 5% of liquidity...
                    if (owner_lp_balance / total_lp_supply) * 100 > 5:
                        if owner == creator:
                            print(f"WARNING: Owner/Creator holds over 5% of the liquidity")
                            report_lines.append(f"WARNING: Owner/Creator holds over 5% of the liquidity")
                        print(f"WARNING: Owner holds over 5% of the liquidity")
                        report_lines.append(f"WARNING: Owner holds over 5% of the liquidity")
                elif holder == creator:
                    report_lines.append(f"\r\nCreator {holder["address"]} holds {holder["balance"]} LP tokens\r\n")
                    creator_lp_balance = holder["balance"]
                    #check if creator holds less than 5% of liquidity...
                    if (creator_lp_balance / total_lp_supply) * 100 > 5:
                        print(f"WARNING: Creator holds over 5% of the liquidity")
                        report_lines.append(f"WARNING: Creator holds over 5% of the liquidity")
                else: report_lines.append(f"\r\n{holder["address"]} holds {holder["balance"]} LP tokens\r\n")

    if 'security' in analysis_types:
        print("\n🔍 Running security checks...")
        security_result = run_security_checks(token_address, chain)
        results['analyses']['security'] = security_result
        check_types = ['Warnings', 'Suspicious URLs', 'Suspicious Addresses']

        report_lines.append("\nSecurity Analysis\n----------------\n")
        if any(security_result):
            for check_type, findings in zip(check_types, security_result):
                if findings:
                    report_lines.append(f"⚠️ WARNING: Found {len(findings)} {check_type}\n")
                    if isinstance(findings, dict):
                        for item, description in findings.items():
                            report_lines.append(f"  - {item}: {description}\n")
                    elif isinstance(findings, list):
                        for item in findings:
                            report_lines.append(f"  - {item}\n")
                    else:
                        report_lines.append(f"  - {findings}\n")
        else:
            report_lines.append("✅ No security issues found\n")

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
            'last_tx_hash': time_since_last_tx["last_tx_hash"],
            'last_active_age': time_since_last_tx["last_active_utc"],
            'inactive_days': time_since_last_tx["inactive_days"]
        }

        report_lines.append("\nLifecycle Analysis\n-------------\n")
        report_lines.append(f"Token Age: {token_age/86400:.2f} days\n")
        if creation_trade_delay:
            report_lines.append(f"Time to First Trade: {creation_trade_delay['time_delay_seconds']/3600:.2f} hours\n")
            report_lines.append(f"Blocks to First Trade: {creation_trade_delay['block_delay']}\n")
            report_lines.append(f"Token Creation Date: {creation_trade_delay['creation_date']}\n")
        if time_since_last_tx:
            report_lines.append(f"Last Active: {time_since_last_tx['last_active_utc']}\n")
            report_lines.append(f"Days Since Last Activity: {time_since_last_tx['inactive_days']} days\n")
            report_lines.append(f"Last Transaction Hash: {time_since_last_tx['last_tx_hash']}\n")
        else:
            report_lines.append("⚠️ Could not determine last active transaction.\n")
    
   
    # Save the report to a file
    report = ''.join(report_lines)
    timestamp = config.datetime.now().strftime('%Y%m%d_%H%M%S')
    report_filename = f"token_analysis_{token_address[:8]}_{filename_suffix}_{timestamp}.txt"
    json_filename = f"token_analysis_{token_address[:8]}_{filename_suffix}_{timestamp}.json"
    
    with open(report_filename, 'w',encoding='utf-8') as f:
        f.write(report)
    
    with open(json_filename, 'w') as f:
        config.json.dump(results, f, indent=4)

    print(f"\n✅ Analysis complete!")
    print(f"📝 Report saved to: {report_filename}")
    print(f"📊 JSON data saved to: {json_filename}")
    
    return results
