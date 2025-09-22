import config

"""----------------------------------------"""
#HELPER FUNCTIONS
def debug_print(*args, **kwargs):
    """
    Print only if global DEBUG flag is set to True
    """
    if config.DEBUG:
        print(*args,**kwargs)

def api_call(params: dict,chain: str):
    """Helper method to perform api calls - Used for DRY

    Args:
        params (dict): Parameters for the API call to insert in the URL.
        chain (str): Used to switch between BscScan and Etherscan.

    Returns:
        Any: Parsed JSON 'result' from the API response, or None on failure
    """
    new_params = {
        'chainid': config.CHAIN_MAP[chain]
    }
    new_params.update(params)
    key = {'apikey': config.ETHERSCAN_API_KEY}
    new_params.update(key)    
    base = config.BASE_URL_SCAN
    url = f"{base}?{config.urlencode(new_params)}"
    #print(url)
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
        return {
            'hash': None,
            'timestamp': None,
            'blocknum': None
        }

def get_creation_to_first_trade_delay(token: str, chain: str) -> dict:
    creation = get_contract_creation_tx(token, chain)
    creation_timestamp = creation["timestamp"]
    creation_blocknum = int(creation["blocknum"])

    txs = get_tx_list(token, creation_blocknum, creation_blocknum + 99, chain)

    if txs:
        for item in txs:
            if item['timeStamp']:
                # Convert timestamps to datetime objects
                trade_timestamp = config.datetime.fromtimestamp(int(item['timeStamp']))
                creation_timestamp_dt = config.datetime.fromtimestamp(int(creation_timestamp))

                debug_print(f"📅 Creation timestamp: {creation_timestamp_dt}")
                debug_print(f"📅 First trade timestamp: {trade_timestamp}")

                # Calculate time and block delay
                age_seconds = (trade_timestamp - creation_timestamp_dt).total_seconds()
                age_days = age_seconds // 86400
                age_hours = (age_seconds % 86400) // 3600
                age_minutes = (age_seconds % 3600) // 60
                block_delay = int(item["blockNumber"]) - creation_blocknum

                debug_print(f"⏱️ Time delay: {int(age_days)} days, {int(age_hours)} hours, {int(age_minutes)} minutes")
                debug_print(f"⛓️ Block delay: {block_delay} blocks")

                # Combine time-based and block-based heuristics
                if block_delay == 0 or age_seconds < 10:
                    debug_print("🔴 Very Suspicious — trade in same block or within 10 seconds\n")
                elif block_delay <= 2 or age_seconds < 30:
                    debug_print("🟠 Possibly Suspicious — near-immediate trade\n")
                elif block_delay <= 10 or age_seconds < 120:
                    debug_print("🟡 Worth Investigating — fast trade\n")
                else:
                    debug_print("🟢 Usually Safe (always DYOR!)\n")

                return {
                    "creation_date": creation_timestamp_dt.isoformat(),
                    "time_delay_seconds": age_seconds,
                    "block_delay": block_delay
                }

        # No transactions with timestamps found in the first 100 blocks
        debug_print("🟢 No transactions found within first 100 blocks — Usually Safe (always DYOR!)\n")
        return {
            "creation_date": config.datetime.fromtimestamp(int(creation_timestamp)).isoformat(),
            "time_delay_seconds": None,
            "block_delay": None
        }

    else:
        debug_print("❌ Error retrieving transaction list!")
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
    # tx_hash = get_contract_creation_tx(token_address,chain)['hash']
    # if(tx_hash == None):
    #     debug_print("error while getting tx hash")
    #     return None
    # blocknum = get_transaction_from_hash(tx_hash,chain)
    # result = get_timestamp_from_blocknum(blocknum,chain)
    # creation_timestamp = config.datetime.fromtimestamp(int(result,16))
    tx = get_contract_creation_tx(token_address,chain)
    creation_timestamp = tx['timestamp']
    creation_timestamp = config.datetime.fromtimestamp(int(creation_timestamp)) if creation_timestamp else None
    current_timestamp = config.datetime.now()

    if creation_timestamp:
        #Compute token age
        age_seconds = (current_timestamp - creation_timestamp).total_seconds()
        #debug_print(creation_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
        #debug_print(current_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
        age_days = age_seconds // 86400
        age_hours = (age_seconds % 86400) // 3600
        age_minutes = (age_seconds % 3600) // 60
        debug_print(f"Token age: {age_days} days, {age_hours} hours, {age_minutes} minutes\n")
        return age_seconds
    else:
        print("Could not retrieve creation timestamp\n")
        return None

def last_active_age(token_address,chain):
    config.scan_rate_limiter.acquire()
    params = {
        'module': 'account',
        'action': 'txlist',
        'address': token_address,
        'startblock': 0,
        'endblock': 'latest',#99999999,
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
    return float(res['result']) if res['result'] else None

def get_token_balance_web3(address: str, token: str, web3: config.Web3, abi: list) -> float:
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

        # Check if balanceOf exists in the ABI
        if not hasattr(contract.functions, "balanceOf"):
            return None

        # Try to call balanceOf
        balance = contract.functions.balanceOf(
            config.Web3.to_checksum_address(address)
        ).call()
        return float(balance)
    except Exception:
        return None

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
        print("Failed to get latest block")
        return None

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
    creation_block = int(creation["blocknum"]) if creation["blocknum"] else None
    last_block = get_latest_tx(token,chain)['blockNumber']
    last_block = int(last_block) if last_block else None
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
    
    def fetch_balance_with_rate_limit(addr):
        config.scan_rate_limiter.acquire()  # ⏳ Waits if rate exceeded
        checksum_addr = config.Web3.to_checksum_address(addr)
        return balance_of(checksum_addr).call()
    
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
            futures = {executor.submit(fetch_balance_with_rate_limit, addr): addr for addr in all_addresses}
            for future in config.tqdm(config.as_completed(futures), total=len(futures)):
                addr = futures[future]
                balance = future.result()
                if balance:
                    holders[addr] = balance  / (10**18)

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
        entry['owner_address'].lower(): float(entry.get('balance', 0))
        for entry in all_owners
        if float(entry.get('balance', 0)) > 0
    }

def is_hardcoded_owner(token,chain,info):
    pattern = r'address\s+(?:public|private|internal)?\s*owner\s*=\s*(0x[a-fA-F0-9]{40})'
    matches = config.re.findall(pattern, info, config.re.IGNORECASE)
    if matches:
        print("🚨 Hardcoded 'owner' address found:")
        for address in matches:
            print(f"   Owner address: {address}")
        return True
    
    print("✅ No hardcoded 'owner' address found.")
    return False

#HOLDER ANALYSIS
def get_owner(token_address,web3):
    owner_abi = [{
        "constant": True,
        "inputs": [],
        "name": "owner",
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function"
    }]
    try:
        token_address = web3.to_checksum_address(token_address)
        contract = web3.eth.contract(address=token_address, abi=owner_abi)
        owner_address = contract.functions.owner().call()
        if owner_address == "0x0000000000000000000000000000000000000000":
            print("🔍 Ownership renounced or null.")
            return owner_address.lower()
        return owner_address.lower()
    except Exception as e:
        print(f"⚠️ Could not fetch owner() for {token_address}: {e}")
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

def get_total_supply_API(token,chain):
    config.scan_rate_limiter.acquire()
    params = {
        'chainid': config.CHAIN_MAP[chain],
        'module': 'stats',
        'action': 'tokensupply',
        'contractaddress': token,
    }
    res = api_call(params,chain)
    return float(res['result']) if res['result'] else None

def get_total_supply_web3(token_address,web3):

    # ERC-20 standard ABI snippet for totalSupply and decimals
    ERC20_ABI = [
        {
            "constant": True,
            "inputs": [],
            "name": "totalSupply",
            "outputs": [{"name": "", "type": "uint256"}],
            "type": "function",
        }
    ]

    if not web3.is_connected():
        raise ConnectionError("Could not connect to the RPC endpoint.")
    
    token_address = web3.to_checksum_address(token_address)
    contract = web3.eth.contract(address=token_address, abi=ERC20_ABI)

    decimals = get_token_decimals(token_address, web3)

    try:
        raw_supply = contract.functions.totalSupply().call()
    except Exception as e:
        raise RuntimeError(f"Could not fetch total supply: {e}")

    human_readable_supply = raw_supply / (10 ** decimals)
    return human_readable_supply

def get_token_decimals(token_address: str, web3: config.Web3, fallback_decimals: int = 18) -> int:
    """
    Fetches the `decimals` value from an ERC-20/BEP-20 token contract.
    Falls back to `fallback_decimals` (default = 18) if the call fails.

    Args:
        token_address (str): The token contract address.
        web3 (Web3): An initialized Web3 instance.
        fallback_decimals (int): The default decimals to use if the contract doesn't respond.

    Returns:
        int: Number of decimals used by the token.
    """
    decimals_abi = [{
        "constant": True,
        "inputs": [],
        "name": "decimals",
        "outputs": [{"name": "", "type": "uint8"}],
        "type": "function"
    }]
    token_address = web3.to_checksum_address(token_address)
    contract = web3.eth.contract(address=token_address, abi=decimals_abi)

    try:
        decimals =  contract.functions.decimals().call()
    except Exception as e:
        print(f"⚠️ Could not fetch decimals for token {token_address}, using fallback {fallback_decimals}. Error: {e}")
        return fallback_decimals
    return decimals

def owner_circulating_supply_analysis(token,chain,owner,total_c_supply,web3: config.Web3,abi):
    debug_print(f"Owner/creator address: {owner}")
    owner_balance = get_token_balance_web3(owner, token, web3,abi)
    if not owner_balance:
        owner_balance = get_token_balance_API(token,owner,chain)
        if not owner_balance:
            owner_percentage,owner_flag = None,None
            return owner_percentage,owner_flag
    owner_percentage = (owner_balance / total_c_supply) * 100 if total_c_supply else 0.0

    owner_flag = owner_percentage > 5

    return owner_percentage,owner_flag

def holder_circulating_supply_analysis(holders,total_c_supply,owner,creator,decimals):
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
    # debug_print(f"Analyzing {len(holders)} unique holders...")
    flagged_holders = []
    if not holders:
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
        if holder == owner or holder == creator: continue
        percentage = (balance / total_c_supply) * 100 if total_c_supply else 0.0
        # Add individual holder details only if they exceed threshold
        if percentage > 5:
            flagged_holders.append({
                'address': holder,
                'balance': balance / (10**decimals),
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

def top10_analysis(holders: dict, total_supply,total_circulating,decimals):
    """
    Returns a dictionary with:
    - top_10 holders (address, balance, percentage of supply)
    - percentage of circulating supply held by top 10
    - compliance flag for <70% rule
    """
    #total_circulating = get_circulating_supply(get_coingecko_id_from_contract(token, chain))
    #total_circulating = get_circulating_supply_estimate(token,chain,holders)
    #total_supply = get_total_supply(token,chain)

    if not holders:
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
        percentage_circ = (balance / total_circulating) * 100 if total_circulating else 0.0
        percentage_tot = (balance / total_supply) * 100 if total_supply else 0.0
        top_10_data.append({
            'address': addr,
            'balance': balance / (10**decimals),
            'percentage_of_total_supply': percentage_tot,
            'percentage_of_circulating_supply': percentage_circ
        })
        total_top_10_balance += balance

    percentage_circ_supply_total = (total_top_10_balance / total_circulating) * 100 if total_circulating else 0.0
    percentage_tot_supply_total = (total_top_10_balance / total_supply) * 100 if total_supply else 0.0

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
    
def is_token_suspicious_by_slippage(token_address: str, chain: str, web3, lp_address, pair_abi, retries: int = 3, retry_delay: float = 1.0):

    def safe_call(fn, label="web3 call"):
        for attempt in range(retries):
            try:
                return fn()
            except Exception as e:
                if attempt == retries - 1:
                    print(f"❌ {label} failed after {retries} attempts: {e}")
                    raise
                config.time.sleep(retry_delay)

    token_address = token_address.lower()

    # Load the pair contract
    pair_address = lp_address.lower()
    pair_contract = web3.eth.contract(
        address=web3.to_checksum_address(pair_address),
        abi=pair_abi
    )

    # Get reserves and token addresses
    try:
        reserves = safe_call(lambda: pair_contract.functions.getReserves().call(), label="getReserves()")
        token0 = safe_call(lambda: pair_contract.functions.token0().call(), label="token0").lower()
        token1 = safe_call(lambda: pair_contract.functions.token1().call(), label="token1").lower()
    except Exception:
        return None

    # Determine input and output reserves
    if token0 == token_address:
        reserve_in_raw = float(reserves[0])
        reserve_out_raw = float(reserves[1])
    elif token1 == token_address:
        reserve_in_raw = float(reserves[1])
        reserve_out_raw = float(reserves[0])
    else:
        print("❌ Token not found in LP pair")
        return None

    if reserve_in_raw == 0 or reserve_out_raw == 0:
        print("⚠️ Invalid LP reserves (0 value detected)")
        return None

    # --- Convert reserves using decimals ---
    decimals = get_token_decimals(token_address, web3)
    scale = 10 ** decimals

    reserve_in = reserve_in_raw / scale
    reserve_out = reserve_out_raw / scale

    fee = 0.003
    slippage_threshold = 5.0  # % threshold for suspicion

    def calculate_slippage(amount_in):
        try:
            spot_price = reserve_out / reserve_in
            expected_output = amount_in * spot_price
            amount_in_with_fee = amount_in * (1 - fee)
            actual_output = (amount_in_with_fee * reserve_out) / (reserve_in + amount_in_with_fee)
            if expected_output == 0:
                return 0.0
            return ((expected_output - actual_output) / expected_output) * 100
        except Exception as e:
            print(f"⚠️ Error in slippage calculation for amount {amount_in}: {e}")
            return 0.0

    # --- Slippage by percentage ---
    trade_percents = [0.001, 0.003, 0.005, 0.01, 0.02]
    percent_slippages = []
    percent_suspicious = False
    first_abnormal_percent = None
    first_abnormal_slippage_percent = None
    percent_suspicion_score = 0

    for pct in trade_percents:
        amount_in = reserve_in * pct
        slippage = calculate_slippage(amount_in)
        percent_slippages.append(slippage)

        if not percent_suspicious and slippage > slippage_threshold:
            percent_suspicious = True
            first_abnormal_percent = pct
            first_abnormal_slippage_percent = slippage
            percent_suspicion_score = round(1 / pct, 2)

    # --- Slippage by fixed input amounts ---
    fixed_inputs = [1, 10, 100, 1000, 10000]  # These are in human-readable token units
    fixed_slippages = []
    fixed_suspicious = False
    first_abnormal_fixed = None
    first_abnormal_slippage_fixed = None
    fixed_suspicion_score = 0

    for fixed_in in fixed_inputs:
        slippage = calculate_slippage(fixed_in)
        fixed_slippages.append(slippage)

        if not fixed_suspicious and slippage > slippage_threshold:
            fixed_suspicious = True
            first_abnormal_fixed = fixed_in
            first_abnormal_slippage_fixed = slippage
            fixed_suspicion_score = fixed_in  # Simple score: lower input = more suspicious

    # Combine results
    overall_suspicious = percent_suspicious or fixed_suspicious
    return {
        "is_suspicious": overall_suspicious,
        "first_abnormal_slippage_percent": first_abnormal_slippage_percent if percent_suspicious else None,
        "first_abnormal_slippage_fixed": first_abnormal_slippage_fixed if fixed_suspicious else None
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

def get_lp_pair(token: str, chain: str,web3) -> tuple:
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
        {
            "constant": True,
            "inputs": [],
            "name": "token0",
            "outputs": [{"name": "", "type": "address"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [],
            "name": "token1",
            "outputs": [{"name": "", "type": "address"}],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [],
            "name": "getReserves",
            "outputs": [
                {"name": "_reserve0", "type": "uint112"},
                {"name": "_reserve1", "type": "uint112"},
                {"name": "_blockTimestampLast", "type": "uint32"},
            ],
            "payable": False,
            "stateMutability": "view",
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [],
            "name": "totalSupply",
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function",
        },
        {
            "constant": True,
            "inputs": [{"name": "", "type": "address"}],
            "name": "balanceOf",
            "outputs": [{"name": "", "type": "uint256"}],
            "stateMutability": "view",
            "type": "function",
        }
    ]

    factory = web3.eth.contract(address=factory_addr, abi=factory_abi)

    token_address = config.Web3.to_checksum_address(token)
    pair_address = factory.functions.getPair(token_address, base_pair_token).call()
    if pair_address == "0x0000000000000000000000000000000000000000":
            print(f"No liquidity pair found for {token}")
            return None, None
    return pair_address,pair_abi

def get_lp_holders(lp_address: str, chain, web3: config.Web3, pair_abi: list,
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
    try:
        balance_of = contract.functions.balanceOf
        use_api = False
    except AttributeError:
        balance_of = None
        use_api = True

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

            addresses_to_check = set()
            for log in logs:
                if len(log["topics"]) >= 3:
                    try:
                        from_addr = config.Web3.to_checksum_address("0x" + log["topics"][1].hex()[-40:])
                        to_addr = config.Web3.to_checksum_address("0x" + log["topics"][2].hex()[-40:])
                        addresses_to_check.update({from_addr,to_addr})
                        for addr in (from_addr, to_addr):
                            if addr not in seen_addresses and addr != "0x0000000000000000000000000000000000000000":
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
            # Remove already seen addresses
            new_addresses = addresses_to_check - seen_addresses
            seen_addresses.update(new_addresses)

            if new_addresses:
                # Use appropriate balance checking method
                with config.ThreadPoolExecutor(max_workers=10) as executor:
                    if use_api:
                        futures = {executor.submit(get_token_balance_API, lp_address, addr,chain): addr for addr in new_addresses}
                    else:
                        futures = {executor.submit(get_token_balance_web3, addr,lp_address,web3,pair_abi): addr for addr in new_addresses}

                    for future in config.as_completed(futures):
                        addr = futures[future]
                        balance = future.result()
                        if balance and balance > 0:
                            holders[addr] = balance
                            if len(holders) >= max_holders:
                                break
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
    creation = get_contract_creation_tx(token, chain)
    creation_block = int(creation["timestamp"]) if creation else None
    if creation_block:
        creation_time = config.datetime.fromtimestamp(creation_block)
    else:
        creation_time = None
    max_lock_duration = 0
    for holder in lp_holders:
        for lock in holder.get("locked_detail") or []:
            end_time_str = lock.get("end_time")
            if not end_time_str:
                continue
            try:
                end_time = config.datetime.fromisoformat(end_time_str.replace("Z", "+00:00"))
                if creation_time:
                    lock_duration = end_time - creation_time
                    if lock_duration > max_lock_duration:
                        max_lock_duration = lock_duration
                if lock_duration.days >= 15:
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
        "lock_duration": lock_duration,
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
                "percent": float(holder.get("percent") or 0.0) * 100,
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

def analyze_lp_security_web3(token_address: str, pair_address: str, owner_address: str, creator_address: str,
                              web3: config.Web3, chain: str,
                              lock_contracts: list,  # addresses of known lock contracts
                              get_contract_creation_tx,    # function that returns creation tx data
                              is_locker,                    # function that checks if an address is a locker
                              ) -> dict:
    """
    Attempts to compute LP security metrics using only on-chain data via web3.
    Checks for whether ≥95% of LP is locked for at least 15 days from token creation.
    """

    # Normalize addresses
    token_address = web3.toChecksumAddress(token_address)
    pair_address = web3.toChecksumAddress(pair_address)
    owner_address = web3.toChecksumAddress(owner_address) if owner_address else None
    creator_address = web3.toChecksumAddress(creator_address) if creator_address else None

    # 1. Get token creation time
    creation_tx = get_contract_creation_tx(token_address, chain)
    if not creation_tx or not creation_tx.get("timestamp"):
        print("❌ Cannot find token creation transaction / timestamp.")
        return {}
    token_creation_ts = int(creation_tx["timestamp"])
    token_creation_time = config.datetime.fromtimestamp(token_creation_ts)

    # 2. Total supply of LP token
    lp_abi_total = [{
        "constant": True,
        "inputs": [],
        "name": "totalSupply",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    }]
    lp_contract = web3.eth.contract(address=pair_address, abi=lp_abi_total)
    try:
        lp_total_supply = lp_contract.functions.totalSupply().call()
    except Exception as e:
        print(f"⚠️ Error fetching totalSupply: {e}")
        lp_total_supply = 0

    # 3. Get LP token decimals
    lp_abi_misc = [
        {"constant": True, "inputs": [], "name": "decimals", "outputs": [{"type": "uint8"}], "stateMutability": "view", "type": "function"},
        {"constant": True, "inputs": [{"name": "account", "type": "address"}], "name": "balanceOf", "outputs":[{"name":"","type":"uint256"}], "stateMutability":"view","type":"function"}
    ]
    lp_token_contract = web3.eth.contract(address=pair_address, abi=lp_abi_misc)
    try:
        lp_decimals = lp_token_contract.functions.decimals().call()
    except Exception:
        lp_decimals = 18

    # 4. Collect holder balances by scanning Transfer logs
    transfer_signature = web3.keccak(text="Transfer(address,address,uint256)").hex()
    latest_block = web3.eth.block_number
    from_block = latest_block - 200000 if latest_block > 200000 else 0 #200000 limit for speed
    step = 5000

    holder_balances = {}  # address -> raw LP token units

    for start in range(from_block, latest_block + 1, step):
        end = min(start + step - 1, latest_block)
        try:
            logs = web3.eth.get_logs({
                "fromBlock": start,
                "toBlock": end,
                "address": pair_address,
                "topics": [transfer_signature]
            })
            for log in logs:
                # topics[1] = from, topics[2] = to
                from_addr = "0x" + log["topics"][1].hex()[-40:]
                to_addr   = "0x" + log["topics"][2].hex()[-40:]
                # decode value
                try:
                    value = web3.codec.decode_single("uint256", bytes.fromhex(log["data"][2:]))
                except Exception:
                    # skip if decode fails
                    continue
                from_low = from_addr.lower()
                to_low = to_addr.lower()
                holder_balances[from_low] = holder_balances.get(from_low, 0) - value
                holder_balances[to_low]   = holder_balances.get(to_low, 0) + value
        except Exception as e:
            print(f"⚠️ Error fetching logs from {start} to {end}: {e}")
            continue

    # Filter non-zero holders
    holders = {addr: bal for addr, bal in holder_balances.items() if bal and bal > 0}

    # 5. Locked LP tokens
    locked_amount = 0
    for addr, balance in holders.items():
        if is_locker(addr, chain):  # your logic to check if address is a locker
            locked_amount += balance

    percent_locked = 100 * locked_amount / lp_total_supply if lp_total_supply else 0.0

    # 6. Check if ≥95% locked for ≥15 days from creation time
    total_locked_for_15_days = 0
    # For each lock contract, check its unlock time and whether the unlock_time is ≥ creation+15 days
    for lock_addr in lock_contracts:
        try:
            lock_contract = web3.eth.contract(
                address=web3.toChecksumAddress(lock_addr),
                abi=[
                    {"constant": True, "inputs": [], "name": "unlockTime", "outputs":[{"type":"uint256"}], "stateMutability":"view","type":"function"},
                    {"constant": True, "inputs":[{"name":"holder","type":"address"}], "name":"lockedAmount", "outputs":[{"type":"uint256"}], "stateMutability":"view","type":"function"}
                ]
            )
            # get unlock time
            unlock_ts = lock_contract.functions.unlockTime().call()
            if unlock_ts is None:
                continue
            unlock_time = config.datetime.fromtimestamp(int(unlock_ts))
            # check required duration
            if (unlock_time - token_creation_time).days >= 15:
                amt = lock_contract.functions.lockedAmount().call()
                total_locked_for_15_days += amt
        except Exception as e:
            print(f"⚠️ Error with lock contract {lock_addr}: {e}")
            continue

    locked_95_for_15d = False
    if lp_total_supply:
        locked_95_for_15d = (total_locked_for_15_days / lp_total_supply) * 100 >= 95

    # 7. Compute creator / owner share of LP
    creator_balance = 0
    owner_balance = 0
    if creator_address and creator_address.lower() in holders:
        creator_balance = holders[creator_address.lower()]
    if owner_address and owner_address.lower() in holders:
        owner_balance = holders[owner_address.lower()]

    creator_percent_of_lp = 100 * creator_balance / lp_total_supply if lp_total_supply else 0
    owner_percent_of_lp   = 100 * owner_balance / lp_total_supply if lp_total_supply else 0

    # 8. Return results
    return {
        "locked_liquidity_percent": round(percent_locked, 4),
        "locked_95_for_15_days_from_creation": locked_95_for_15d,
        "token_creation_time": token_creation_time.isoformat(),
        "creator_percent_of_lp": round(creator_percent_of_lp, 4),
        "owner_percent_of_lp": round(owner_percent_of_lp, 4),
        "total_lp_supply": lp_total_supply / (10 ** lp_decimals) if lp_decimals else lp_total_supply,
        "holders_count": len(holders),
        "holders": [
            {"address": addr, "balance": bal / (10 ** lp_decimals)}
            for addr, bal in holders.items()
        ]
    }

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
    creation_block = int(creation["blocknum"]) if creation["blocknum"] else None
    print(f"📦 LP Creation Block: {creation_block}")

    # 🧾 Step 3: Get LP holders and balances
    holders = get_lp_holders(lp_address, chain,web3, pair_abi, from_block=creation_block, to_block=to_block, chain=chain)
    
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
    with open("data/locking_selectors_inverted.json", "r", encoding="utf-8", errors="replace") as f:
        selector_to_method = config.json.load(f)  # dict: e.g. { "0xa9059cbb": "transfer(address,uint256)" }

    # Get contract creation info
    creation = get_contract_creation_tx(token, chain)
    creation_blocknum = int(creation["blocknum"]) if creation["blocknum"] else None

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
    if high:
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

def isburner(address,chain,creation_blocknum = 0,last_block = 0):
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
    creation_blocknum = int(creation["blocknum"]) if creation["blocknum"] else None
    last_tx = get_latest_tx(token,chain)
    last_block = int(last_tx['blockNumber']) if creation_blocknum and last_tx else 'latest'

    params = {
        'module': 'account',
        'action': 'tokentx',
        'contractaddress': token,
        'startblock': creation_blocknum,
        'endblock': last_block,
        'sort': 'asc',
    }
    if not creation["blocknum"]:
        print("No creation block found, can't get token transfers")
        return None
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
        return {
            'hash': None,
            'timestamp': None,
            'blocknum': None
        }

def get_account_token_transfers(address,chain):
    config.scan_rate_limiter.acquire()
    tx = get_first_account_tx(address, chain)['blocknum'] or get_contract_creation_tx(address, chain)['blocknum']
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

def islocker(address, chain):
    known_lockers = {
        "eth": {
            "unicrypt_v4": "0x6a76da1eb2cbe8b0d52cfe122c4b7f0ca5a940ef",
            "unicrypt_v3": "0xFD235968e65B0990584585763f837A5b5330e6DE",
            "unicrypt_v2_uniswap": "0x663A5C229c09b049E36dCc11a9B0d4a8Eb9db214",
            "unicrypt_v2_sushiswap": "0xED9180976c2a4742C7A57354FD39d8BEc6cbd8AB",
            "unicrypt_vesting": "0xDba68f07d1b7Ca219f78ae8582C213d975c25cAf"
        },
        "bsc": {
            "unicrypt_v3": "0xfe88DAB083964C56429baa01F37eC2265AbF1557",
            "unicrypt_v1_pancakeswap": "0xc8B839b9226965caf1d9fC1551588AaF553a7BE6",
            "unicrypt_v2_pancakeswap": "0xC765bddB93b0D1c1A88282BA0fa6B2d00E3e0c83",
            "unicrypt_v2_uniswap": "0x7229247bD5cf29FA9B0764Aa1568732be024084b",
            "unicrypt_julswap": "0x1f23742D882ace96baCE4658e0947cCCc07B6a75",
            "unicrypt_biswap": "0x74dEE1a3E2b83e1D1F144Af2B741bbAFfD7305e1",
            "unicrypt_vesting": "0xeaEd594B5926A7D5FBBC61985390BaAf936a6b8d",
            "team_finance": "0x0c89c0407775dd89b12918b9c0aa42bf96518820",
            "UNCX_locker": "0xC765bddB93b0D1c1A88282BA0fa6B2d00E3e0c83"
        },
        "solana": {}  # Placeholder — implement if needed
    }

    # Normalize the input address
    address = address.lower()

    # Get locker addresses for the given chain
    locker_addresses = known_lockers.get(chain.lower(), {}).values()

    # Check if the address is one of the known locker addresses
    return address in (locker.lower() for locker in locker_addresses)

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
    if not source_code:
        return []
    functions = []
    inside_function = False
    brace_count = 0
    current_function = []

    # You don’t need to parse JSON — assume the string is Solidity code
    simplified_contracts = {
        "contract.sol": source_code
    }

    # Regex pattern to detect function start
    function_start_pattern = config.re.compile(
        r'\bfunction\b\s+[\w\d_]+\s*\([^)]*\)\s*(public|private|internal|external)?[\s\w]*\{',
        config.re.MULTILINE
    )

    for filename, code in simplified_contracts.items():
        lines = code.splitlines()

        for line in lines:
            stripped = line.strip()

            if not inside_function:
                if function_start_pattern.search(stripped):
                    inside_function = True
                    brace_count = stripped.count('{') - stripped.count('}')
                    current_function = [line]
                    if brace_count == 0:
                        functions.append('\n'.join(current_function))
                        inside_function = False
            else:
                current_function.append(line)
                brace_count += line.count('{') - line.count('}')
                if brace_count == 0:
                    functions.append('\n'.join(current_function))
                    inside_function = False

    return functions

def analyze_token_contract_with_snippets(source_code: str, pbar=None) -> dict:
    findings = {}
    funcs = extract_all_functions(source_code)
    normalized_funcs = [(f.strip(), f.strip().lower()) for f in funcs]    
    malicious_patterns = {
        'honeypot_mechanics': [
            # Transfer blocking through gas manipulation
            r'require\s*\(\s*gasleft\(\)\s*[<>]=?\s*\d+\s*\)',
            r'assembly\s*{\s*[^}]*gas\s*[^}]*revert',
            r'if\s*\(\s*msg\.sender\s*!=\s*tx\.origin\s*\)\s*{\s*revert',
            # Dynamic fee traps
            r'_fee\s*=\s*\(\s*amount\s*\*\s*\d+\s*\)',
            r'require\s*\(\s*balanceOf\[msg\.sender\]\s*>=\s*_calculateFee',
            # Hidden state conditions
            r'bool\s+private\s+_tradingEnabled\s*=\s*false',
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*private\s*_canTrade',
            # Deceptive transfer logic
            r'function\s+transfer.*{\s*return\s+true;\s*}',
            r'function\s+transferFrom.*{\s*return\s+false;\s*}'
        ],

        'minting_mechanics': [
            r'function\s+mint\s*\(',
            r'_mint\s*\(\s*[^)]*\)',
            r'emit\s+Transfer\s*\(\s*address\(0\)',
        ],

        'ownership_manipulation': [
            # Hidden owner patterns
            r'address\s+private\s+constant\s+_owner\s*=\s*address\(',
            r'_owner\s*=\s*address\s*\(\s*uint160\s*\(\s*uint256\s*\(\s*keccak256',
            # Multiple ownership mechanisms
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*private\s*_owners',
            r'bool\s+public\s+renounced;\s*.*function\s+renounceOwnership',
            # Stealth admin controls
            r'modifier\s+onlyAdmin\s*{\s*require\s*\(\s*_admins\[msg\.sender\]',
            r'function\s+setController\s*\(\s*address\s*\)\s*external'
        ],

        'transfer_blocking': [
            # Block sells based on pair address
            r'if\s*\(\s*to\s*==\s*pancakePair\)\s*{\s*require\s*\(\s*false',
            r'require\s*\(\s*!automatedMarketMakerPairs\[to\]\s*\)',
            # Time-based locks
            r'require\s*\(\s*tradingEnabledTimestamp\s*[<>]=?\s*block\.timestamp',
            r'cooldownTimer\[sender\]\s*=\s*block\.timestamp',
            # Complex transfer restrictions
            r'if\s*\(\s*amount\s*>\s*maxTxAmount\s*&&\s*!_isExcluded\[sender\]',
            r'require\s*\(\s*whitelist\[msg\.sender\]\s*\|\|\s*!tradingEnabled'
        ],

        'stealth_fee_mechanics': [
            # Hidden fee calculations
            r'uint256\s+private\s+constant\s+MAX_FEE\s*=\s*\d{2,}',
            r'function\s+_calculateFee.*internal',
            # Dynamic fee adjustments
            r'if\s*\(\s*block\.number\s*-\s*lastTrade\[sender\]\s*<\s*\d+\)\s*{\s*fee',
            r'sellFee\s*=\s*previousFee\s*\*\s*2',
            # Fee bypass checks
            r'mapping\s*\(\s*address\s*=>\s*bool\s*\)\s*private\s*_isExcludedFromFee',
            r'function\s+excludeFromFee\s*\(\s*address\s*\)\s*external\s*onlyOwner'
        ],

        'liquidity_manipulation': [
            # Liquidity removal tricks
            r'function\s+removeLiquidity.*onlyOwner',
            r'function\s+migrate\(\).*{\s*.*transfer\(.*LP',
            # Lock bypass mechanisms
            r'function\s+unlock.*{\s*lockTime\s*=\s*block\.timestamp',
            r'function\s+updatePair.*external\s*onlyOwner',
            # Stealth drain functions
            r'function\s+sweep\s*\(\s*address\s*token\s*\)',
            r'function\s+emergencyWithdraw'
        ],

        'router_manipulation': [
            # Router/pair manipulation
            r'function\s+setRouterAddress.*onlyOwner',
            r'pancakeRouter\s*=\s*IPancakeRouter02',
            # Trading path manipulation
            r'path\[0\]\s*=\s*address\(this\);\s*path\[1\]\s*=\s*pancakeRouter',
            r'function\s+updatePath.*onlyOwner',
            # Swap blocking
            r'require\s*\(\s*!inSwap\s*\)',
            r'modifier\s+lockTheSwap'
        ],

        'balance_manipulation': [
            # Double balance updates
            r'balances\[to\]\s*\+=\s*amount.*balances\[to\]\s*\+=',
            r'_rOwned\[to\]\s*=\s*_rOwned\[to\]\s*\+\s*\(',
            # Hidden balance modifiers
            r'function\s+_beforeTokenTransfer.*{\s*_balances',
            r'function\s+syncBalance.*assembly',
            # Reflection manipulation
            r'_getCurrentSupply.*_rTotal',
            r'_getRate\(\).*_rTotal\s*-\s*_rOwned'
        ],

        'anti_analysis_features': [
            # Contract size checks
            r'extcodesize\s*\(\s*msg\.sender\s*\)\s*==\s*0',
            r'require\s*\(\s*tx\.origin\s*==\s*msg\.sender',
            # Bot detection
            r'block\.timestamp\s*-\s*lastTrade\[msg\.sender\]\s*<',
            r'require\s*\(\s*gasleft\(\)\s*>=\s*minGas',
            # Analysis prevention
            r'assembly\s*{\s*jump\(pc\(\)\s*\+\s*\d+\)\s*}',
            r'selfdestruct\s*\(\s*payable\s*\(\s*owner\s*\)\s*\)'
        ],

        'emergencyFunctions': [
            # Emergency controls
            r'function\s+pause\s*\(\s*\)\s*external\s*onlyOwner',
            r'function\s+unpause\s*\(\s*\)\s*external\s*onlyOwner',
            # Token recovery
            r'function\s+rescueToken.*{\s*IERC20\(token\)\.transfer',
            r'function\s+drain\s*\(\s*\)\s*external\s*onlyOwner',
            # Contract destruction
            r'function\s+kill\s*\(\s*\)\s*external\s*onlyOwner',
            r'selfdestruct\s*\(\s*payable\s*\(\s*msg\.sender\s*\)\s*\)' #SWC 106
        ]
    }

    results = {}
    total_matches = 0


    for category, patterns in malicious_patterns.items():
        matching_snippets = []

        for pattern in patterns:
            regex = config.re.compile(pattern, config.re.IGNORECASE)

            for original_func, normalized_func in normalized_funcs:
                for match in regex.finditer(normalized_func):
                    snippet = {
                        'matched_code': match.group(),
                        'function_context': original_func,
                        'pattern': pattern
                    }
                    matching_snippets.append(snippet)

        if matching_snippets:
            results[category] = {
                'count': len(matching_snippets),
                'snippets': matching_snippets
            }
            total_matches += len(matching_snippets)

        if pbar:
            pbar.update(1 / len(malicious_patterns))
    return {
        'total_matches': total_matches,
        'patterns_found': results
    }

"""----------------------------------------"""

def get_coingecko_id_from_contract(contract_address, chain):
    chain_map = {
        'bsc': 'binance-smart-chain',
        'eth': 'ethereum'
    }
    if chain not in chain_map:
        raise ValueError(f"Unsupported chain: {chain}")
    
    please = {
            '0xa49d7499271ae71cd8ab9ac515e6694c755d400c': 'mute',
            '0x26a604dffe3ddab3bee816097f81d3c4a2a4cf97': 'corionx',
            '0x8baf5d75cae25c7df6d1e0d26c52d19ee848301a': 'catalorian',
            '0xec12ba5ac0f259e9ac6fc9a3bc23a76ad2fde5d9': 'hugewin',
            '0xfbd5fd3f85e9f4c5e8b40eec9f8b8ab1caaa146b': 'treat-token',
            '0xa2b8e02ce95b54362f8db7273015478dd725d7e7': 'meme-cup',
            '0x4b7ffcb2b92fb4890f22f62a52fb7a180eab818e': 'diva-protocol',
            '0x76bc677d444f1e9d57daf5187ee2b7dc852745ae': 'offshift',
            '0xa6c0c097741d55ecd9a3a7def3a8253fd022ceb9': 'concierge-io',
            '0x0b38210ea11411557c13457d4da7dc6ea731b88a': 'api3',
            '0x0aee8703d34dd9ae107386d3eff22ae75dd616d1': 'tranche-finance',
            '0x06ddb3a8bc0abc14f85e974cf1a93a6f8d4909d9': '8pay',
            '0x73374ea518de7addd4c2b624c0e8b113955ee041': 'juggernaut',
            '0x17837004ea685690b32dbead02a274ec4333a26a': 'bear-inu',
            '0x75e88b8c2d34a52a6d36deada664d7dc9116e4ef': 'zaros',
            '0x60e254e35dd712394b3aba7a1d19114732e143dd': 'rivusdao',
            '0x7b66e84be78772a3afaf5ba8c1993a1b5d05f9c2': 'vitarna',
            '0x9be89d2a4cd102d8fecc6bf9da793be995c22541': 'binance-wrapped-btc',
            '0x249ca82617ec3dfb2589c4c17ab7ec9765350a18': 'verse-bitcoin',
            '0x285db79fa7e0e89e822786f48a7c98c6c1dc1c7d': 'magic-internet-cash',
            '0xa0084063ea01d5f09e56ef3ff6232a9e18b0bacd': 'cyberdex',
            '0xe973e453977195422b48e1852a207b7ee9c913c7': 'adreward',
            '0xd8c978de79e12728e38aa952a6cb4166f891790f': 'og-roaring-kitty',
            '0x68aae81b4241ffe03d3552d42a69940604fe28bf': 'muffin',
            '0x4e4990e997e1df3f6b39ff49384e2e7e99bc55fe': 'saudi-bonk',
            '0xc8d3dcb63c38607cb0c9d3f55e8ecce628a01c36': 'matrixswap',
            '0x6069c9223e8a5da1ec49ac5525d4bb757af72cd8': 'musk-gold',
            '0x48f9e38f3070ad8945dfeae3fa70987722e3d89c': 'infinifi-usd',
            '0x7afd0d633e0a2b1db97506d97cadc880c894eca9': 'marutaro-2',
            '0xaddb6dc7e2f7caea67621dd3ca2e8321ade33286': 'sharp-ai',
            '0xf293d23bf2cdc05411ca0eddd588eb1977e8dcd4': 'sylo',
            '0xd5930c307d7395ff807f2921f12c5eb82131a789': 'bolt',
            '0x4ae149fd6059af772b962efac6bf0236872d6940': 'lemmy-the-bat',
            '0xcab84bc21f9092167fcfe0ea60f5ce053ab39a1e': 'block-4',
            '0x82d36570842fc1ac2a3b4dbe0e7c5c0e2e665090': 'nfinityai',
            '0xf57e7e7c23978c3caec3c3548e3d615c346e79ff': 'immutable-x',
            '0xd2adc1c84443ad06f0017adca346bd9b6fc52cab': 'dfund',
            '0x54991328ab43c7d5d31c19d1b9fa048e77b5cd16': 'soil',
            '0x35bd01fc9d6d5d81ca9e055db88dc49aa2c699a8': 'friends-with-benefits-pro',
            '0xff8c479134a18918059493243943150776cf8cf2': 'renq-finance',
            '0x381491960c37b65862819ced0e35385f04b2c78b': 'hachiko-2',
            '0x89e8e084cc60e6988527f0904b4be71656e8bfa9': 'smog',
            '0x2d5d69da90b4c02b95c802344b48e3e57ce220d7': 'beware-of-geeks-bearing-grifts',
            '0x3541a5c1b04adaba0b83f161747815cd7b1516bc': 'citadao',
            '0x9393fdc77090f31c7db989390d43f454b1a6e7f3': 'dark-energy-crystals',
            '0xd073e6341a3aa6c4d94c4f8f20fbd1ede572b0da': 'metacene',
            '0x270b7748cdf8243bfe68face7230ef0fce695389': 'hinkal-staked-eth',
            '0xbb8ecf8d1342e086c9a751ee1b31a8320007379f': 'nexara',
            '0x2f573070e6090b3264fe707e2c9f201716f123c7': 'mumu',
            '0x5bb29c33c4a3c29f56f8aca40b4db91d8a5fe2c5': 'one-share',
            '0xff931a7946d2fa11cf9123ef0dc6f6c7c6cb60c4': 'dancing-baby',
            '0x44108f0223a3c3028f5fe7aec7f9bb2e66bef82f': 'across-protocol',
            '0x3301ee63fb29f863f2333bd4466acb46cd8323e6': 'akita-inu',
            '0x0808e6c4400bde1d70db0d02170b67de05e07ef5': 'wrapped-lyx-sigmaswap',
            '0xac6708e83698d34cd5c09d48249b0239008d0ccf': 'fort-knox',
            '0xe842e272a18625319cc36f64eb9f97e5ad0c32af': 'yak',
            '0x004f747a91e05d0e2fbe8bf3cd39cdb2bcfab02c': 'tweet',
            '0x28e67eb7aaa8f5dd9cb7be2b2e3dad6b25edb1ab': 'freaky-keke',
            '0x80f0c1c49891dcfdd40b6e0f960f84e6042bcb6f': 'dbxen',
            '0x8fe815417913a93ea99049fc0718ee1647a2a07c': 'xswap-2',
            '0x4947b72fed037ade3365da050a9be5c063e605a7': 'peanut-2',
            '0x39795344cbcc76cc3fb94b9d1b15c23c2070c66d': 'seigniorage-shares',
            '0x926759a8eaecfadb5d8bdc7a9c7b193c5085f507': 'nura-labs',
            '0x8561d6829189db74ea1165b7d2bc633616891695': 'flo',
            '0x7434a5066dc317fa5b4d31aaded5088b9c54d667': 'cult',
            '0x8c543aed163909142695f2d2acd0d55791a9edb9': 'velas',
            '0xcda4e840411c00a614ad9205caec807c7458a0e3': 'purefi',
            '0x955d5c14c8d4944da1ea7836bd44d54a8ec35ba1': 'refund',
            '0x8074836637eb9cc73a01a65d5700907fc639c4e9': 'duelnow',
            '0x940a2db1b7008b6c776d4faaca729d6d4a4aa551': 'dusk-network',
            '0x14cf922aa1512adfc34409b63e18d391e4a86a2f': 'eth-strategy',
            '0xdbdb4d16eda451d0503b854cf79d55697f90c8df': 'alchemix',
            '0x2620638eda99f9e7e902ea24a285456ee9438861': 'crust-storage-market',
            '0x8ab2ff0116a279a99950c66a12298962d152b83c': 'ordiswap-token',
            '0x147faf8de9d8d8daae129b187f0d02d819126750': 'geodb',
            '0xf75302720787c2a2176c87b1919059c4eaac8b98': 'cfgi',
            '0x38d64ce1bdf1a9f24e0ec469c9cade61236fb4a0': 'vector-eth',
            '0x1634e10c9155be623b5a52d6ca01c7a904d89b0a': 'this-is-fine-ethereum',
            '0x6adb2e268de2aa1abf6578e4a8119b960e02928f': 'shibadoge',
            '0x25931894a86d47441213199621f1f2994e1c39aa': 'chaingpt',
            '0x677ddbd918637e5f2c79e164d402454de7da8619': 'vesper-vdollar',
            '0x9e3b5582b22e3835896368017baff6d942a41cd9': 'haven1',
            '0xa1f410f13b6007fca76833ee7eb58478d47bc5ef': 'rejuve-ai',
            '0xba25b2281214300e4e649fead9a6d6acd25f1c0a': 'tree-capital',
            '0xf1f955016ecbcd7321c7266bccfb96c68ea5e49b': 'rally-2',
            '0x62959c699a52ec647622c91e79ce73344e4099f5': 'define',
            '0x33f391f4c4fe802b70b77ae37670037a92114a7c': 'burp',
            '0x830a8512db4f6fca51968593e2667156c2c483a8': 'wen-token',
            '0xc08512927d12348f6620a698105e1baac6ecd911': 'gyen',
            '0xfc10cd3895f2c66d6639ec33ae6360d6cfca7d6d': 'yes-3',
            '0xfbe44cae91d7df8382208fcdc1fe80e40fbc7e9a': 'the-next-gem-ai',
            '0x1258d60b224c0c5cd888d37bbf31aa5fcfb7e870': 'nodeai',
            '0x9b0b23b35ad8136e6181f22b346134ce5f426090': 'cinogames',
            '0x71ab77b7dbb4fa7e017bc15090b2163221420282': 'highstreet',
            '0xdc5e9445169c73cf21e1da0b270e8433cac69959': 'ketaicoin',
            '0x255494b830bd4fe7220b3ec4842cba75600b6c80': 'beast-seller',
            '0x678e840c640f619e17848045d23072844224dd37': 'cratos',
            '0xb74f399aac8335e44a50ffb8f7ece74b9db8c30e': 'nala',
            '0xd555498a524612c67f286df0e0a9a64a73a7cdc7': 'defrogs',
            '0x419905009e4656fdc02418c7df35b1e61ed5f726': 'resupply',
            '0x384efd1e8b05c23dc392a40cb4e515e2229a5243': 'healix-ai',
            '0xe34ba9cbdf45c9d5dcc80e96424337365b6fe889': 'medusa-3',
            '0xb244b3574a5627849fca2057e3854340def63071': 'veil-exchange',
            '0xc092a137df3cf2b9e5971ba1874d26487c12626d': 'ring-ai',
            '0xb58e61c3098d85632df34eecfb899a1ed80921cb': 'frankencoin',
            '0x5e362eb2c0706bd1d134689ec75176018385430b': 'decentralized-validator-token',
            '0x00000000051b48047be6dc0ada6de5c3de86a588': 'baby-shiba-inu-erc',
            '0xc00e94cb662c3520282e6f5717214004a7f26888': 'compound-governance-token',
            '0x3cb48aeb3d1abadc23d2d8a6894b3a68338381c2': 'paladinai',
            '0x0138f5e99cfdffbacf36e543800c19ef16fa294b': 'prophet-3',
            '0x8143182a775c54578c8b7b3ef77982498866945d': 'wrapped-quil',
            '0x993864e43caa7f7f12953ad6feb1d1ca635b875f': 'singularitydao',
            '0xfa5047c9c78b8877af97bdcb85db743fd7313d4a': 'rook',
            '0x6f2dec5da475333b0af4a3ffc9a33b0211a9a452': 'cryptotwitter',
            '0xe0ad1806fd3e7edf6ff52fdb822432e847411033': 'onx-finance',
            '0x5bdc32663ec75e85ff4abc2cae7ae8b606a2cfca': 'cookies-protocol',
            '0x5582a479f0c403e207d2578963ccef5d03ba636f': 'salad',
            '0x53be7be0ce7f92bcbd2138305735160fb799be4f': 'neutaro',
            '0x1cf4592ebffd730c7dc92c1bdffdfc3b9efcf29a': 'waves',
            '0x09395a2a58db45db0da254c7eaa5ac469d8bdc85': 'subquery-network',
            '0x814a870726edb7dfc4798300ae1ce3e5da0ac467': 'dacat',
            '0x3c8d2fce49906e11e71cb16fa0ffeb2b16c29638': 'nifty-league',
            '0x05fe069626543842439ef90d9fa1633640c50cf1': 'eve-ai',
            '0xe1ec350ea16d1ddaff57f31387b2d9708eb7ce28': 'pepechain',
            '0x5f18ea482ad5cc6bc65803817c99f477043dce85': 'agility',
            '0xef8e456967122db4c3c160314bde8d2602ad6199': 'wagmi-coin',
            '0x91af0fbb28aba7e31403cb457106ce79397fd4e6': 'aergo',
            '0x9ab778f84b2397c7015f7e83d12eee47d4c26694': 'bitecoin-2',
            '0xfa704148d516b209d52c2d75f239274c8f8eaf1a': 'octaspace',
            '0x06561dc5cedcc012a4ea68609b17d41499622e4c': 'noob',
            '0x64b78325d7495d6d4be92f234fa3f3b8d8964b8b': 'shopping-io-token',
            '0x2c0687215aca7f5e2792d956e170325e92a02aca': 'earth-2-essence',
            '0x1559fa1b8f28238fd5d76d9f434ad86fd20d1559': 'eden',
            '0xf5f52266a57e6d7312da39bd7ab9527b9e975c40': 'agent-virtual-machine',
            '0x8ccd897ca6160ed76755383b201c1948394328c7': 'balance-ai',
            '0xc36983d3d9d379ddfb306dfb919099cb6730e355': 'colle-ai',
            '0x81987681443c156f881b70875724cc78b08ada26': 'mirai-the-whiterabbit',
            '0xd16fd95d949f996e3808eeea0e3881c59e76ef1e': 'paratoken-2',
            '0x27f103f86070cc639fef262787a16887d22d8415': 'fofo-token',
            '0xfbb4f63821e706daf801e440a5893be59094f5cc': 'faith-2',
            '0x9ba77c059b5a59a220aa648a6bd97986fb1bf0a9': 'agentsys-ai',
            '0x103c45ffcf40f481a318480718501527929a89c3': 'fragma',
            '0x2c7f442aab99d5e18cfae2291c507c0b5f3c1eb5': 'keko',
            '0x0a9e3dde12e4519c9d89df69bd738490c9466bf4': 'market-dominance',
            '0xc9fe6e1c76210be83dc1b5b20ec7fd010b0b1d15': 'fringe-finance',
            '0xaf4144cd943ed5362fed2bae6573184659cbe6ff': 'lizcoin',
            '0x5362ca75aa3c0e714bc628296640c43dc5cb9ed6': 'dejitaru-hoshi',
            '0x3ffeea07a27fab7ad1df5297fa75e77a43cb5790': 'peipeicoin-vip',
            '0x4e9fcd48af4738e3bf1382009dc1e93ebfce698f': 'tao-inu',
            '0x0fc2a55d5bd13033f1ee0cdd11f60f7efe66f467': 'lagrange',
            '0x397deb686c72384fad502a81f4d7fdb89e1f1280': 'xels',
            '0xf02c2dc9b3cb7f1ba21ccd82dff4ebc92da8996f': 'tensorscan-ai',
            '0x217ddead61a42369a266f1fb754eb5d3ebadc88a': 'don-key',
            '0xfb130d93e49dca13264344966a611dc79a456bc5': 'dogegf',
            '0x5de869e3e62b0fb2c15573246ba3bb3fd97a2275': 'sheboshis-2',
            '0xb5130f4767ab0acc579f25a76e8f9e977cb3f948': 'godcoin-2',
            '0x96665680f4889891f3209713cb9a8205dce7278d': 'nyx-cipher',
            '0x799ebfabe77a6e34311eeee9825190b9ece32824': 'braintrust',
            '0xed4e879087ebd0e8a77d66870012b5e0dffd0fa4': 'astropepex',
            '0xf59c6767dfb5aa9e908cb8d1831d02e53312e8ff': 'eyzoai',
            '0xb1c064c3f2908f741c9dea4afc5773238b53e6cc': 'warioxrpdumbledoreyugioh69inu',
            '0xebb66a88cedd12bfe3a289df6dfee377f2963f12': 'oscar',
            '0x52662717e448be36cb54588499d5a8328bd95292': 'tenshi',
            '0x8c9532a60e0e7c6bbd2b2c1303f63ace1c3e9811': 'renzo-restaked-lst',
            '0x83e9f223e1edb3486f876ee888d76bfba26c475a': 'blockchainspace',
            '0xcb76314c2540199f4b844d4ebbc7998c604880ca': 'strawberry-ai',
            '0x1a11ea9d61588d756d9f1014c3cf0d226aedd279': 'milei-token',
            '0x666acd390fa42d5bf86e9c42dc2fa6f6b4b2d8ab': 'gorth',
            '0x473037de59cf9484632f4a27b509cfe8d4a31404': 'green-satoshi-token-on-eth',
            '0x473f4068073cd5b2ab0e4cc8e146f9edc6fb52cc': 'nutcoin-meme',
            '0x2015bc0be96be4aea2aabc95522109acfec84c30': 'weth-hedz',
            '0x6df0e641fc9847c0c6fde39be6253045440c14d3': 'dinero-2',
            '0xd8dd38ca016f3e0b3bc545d33cce72af274ce075': 'swing-xyz',
            '0x910812c44ed2a3b611e4b051d9d83a88d652e2dd': 'pledge-2',
            '0x782f97c02c6ace8a3677c4a4c495d048ad67dba2': 'social-lens-ai',
            '0xc4c75f2a0cb1a9acc33929512dc9733ea1fd6fde': 'martin-shkreli-inu',
            '0x584bc13c7d411c00c01a62e8019472de68768430': 'hegic',
            '0x0000000000c5dc95539589fbd24be07c6c14eca4': 'milady-cult-coin',
            '0x28e58ee9932697f610de907a279684d30c407ba9': 'depinet',
            '0x9acb099a6460dead936fe7e591d2c875ae4d84b8': 'tokabu',
            '0x270ca21eb1a37cfe0e9a0e7582d8f897e013cdff': 'dogius-maximus',
            '0x19af07b52e5faa0c2b1e11721c52aa23172fe2f5': 'memes-street',
            '0xb01dd87b29d187f3e3a4bf6cdaebfb97f3d9ab98': 'liquity-bold',
            '0xea36af87df952fd4c9a05cd792d370909bbda8db': 'official-k-pop',
            '0x65278f702019078e9ab196c0da0a6ee55e7248b7': 'wrapped-dione',
            '0xf418588522d5dd018b425e472991e52ebbeeeeee': 'ethereum-push-notification-service',
            '0x87de305311d5788e8da38d19bb427645b09cb4e5': 'verox',
            '0xb6ff96b8a8d214544ca0dbc9b33f7ad6503efd32': 'sync-network',
            '0x8f081eb884fd47b79536d28e2dd9d4886773f783': 'bepay',
            '0xf411903cbc70a74d22900a5de66a2dda66507255': 'verasity',
            '0x7bc3485026ac48b6cf9baf0a377477fff5703af8': 'wrapped-aave-ethereum-usdt',
            '0x75d86078625d1e2f612de2627d34c7bc411c18b8': 'agii',
            '0x46fdcddfad7c72a621e8298d231033cc00e067c6': 'department-of-government-efficiency-3',
            '0xd8695414822e25ab796c1d360914ddf510a01138': 'kreaitor',
            '0xaf8b894229bc800658ab0faf744e97c8c74c4321': 'black-lemon-ai',
            '0x817162975186d4d53dbf5a7377dd45376e2d2fc5': 'reactive-network',
            '0x4550003152f12014558e5ce025707e4dd841100f': 'kaizen',
            '0xaee433adebe0fbb88daa47ef0c1a513caa52ef02': 'pontoon',
            '0x73d7c860998ca3c01ce8c808f5577d94d545d1b4': 'ix-swap',
            '0x8236a87084f8b84306f72007f36f2618a5634494': 'lombard-staked-btc',
            '0x7849241ccff81511f26c2a86ef9d96624e948975': 'acore-ai-token',
            '0xe9732d4b1e7d3789004ff029f032ba3034db059c': 'patriot',
            '0xd86571bfb6753c252764c4ae37fd54888774d32e': 'kabosu-erc20',
            '0x38e68a37e401f7271568cecaac63c6b1e19130b4': 'banana-gun',
            '0xca76bf98b6e44df7360da8650e701f6d9d94bb58': 'memelinked',
            '0x24da31e7bb182cb2cabfef1d88db19c2ae1f5572': 'shikoku',
            '0x80122c6a83c8202ea365233363d3f4837d13e888': 'messier',
            '0xd9ebbc7970e26b4eced7323b9331763e8272d011': 'benji-bananas',
            '0x3be7bf1a5f23bd8336787d0289b70602f1940875': 'vidt-dao',
            '0xcb43c88c980ff3a2c3f45f125d9886e7aabcd017': 'freakoff',
            '0x256d1fce1b1221e8398f65f9b36033ce50b2d497': 'alvey-chain',
            '0x6006fc2a849fedaba8330ce36f5133de01f96189': 'spaceswap-shake',
            '0x52c7aa73dc430dab948eee73ea253383fd223420': 'big-back-bitcoin',
            '0x50327c6c5a14dcade707abad2e27eb517df87ab5': 'wrapped-tron',
            '0x75231f58b43240c9718dd58b4967c5114342a86c': 'okb',
            '0xcbfef8fdd706cde6f208460f2bf39aa9c785f05d': 'kine-protocol',
            '0x2559813bbb508c4c79e9ccce4703bcb1f149edd7': 'hourglass',
            '0x2047ab3072b52561596ce5e0131bdbb7c848538d': 'bored',
            '0x3256cade5f8cb1256ac2bd1e2d854dec6d667bdf': 'mogutou',
            '0x478156deabfac918369044d52a6bdb5cc5597994': 'schrodinger-2',
            '0xb2617246d0c6c0087f18703d576831899ca94f01': 'zignaly',
            '0xb0415d55f2c87b7f99285848bd341c367feac1ea': 'r0ar-token',
            '0xf38deb975d9a34bc2b8f678de0c1d53692363851': 'metabrawl',
            '0xe7f58a92476056627f9fdb92286778abd83b285f': 'decentraweb',
            '0x3595e426a7808e2482667ee4e453ef280fbb9cf4': 'nose-candy',
            '0xe75f2acafba1ad56c5ed712ffbc1d31910e74396': 'komputai',
            '0x5fc111f3fa4c6b32eaf65659cfebdeed57234069': '0xgasless-2',
            '0x740a5ac14d0096c81d331adc1611cf2fd28ae317': 'plebz',
            '0xaf05ce8a2cef336006e933c02fc89887f5b3c726': 'lockheed-martin-inu',
            '0x5e29cf3e3fed4df50acab95f8268e9ee26ea36f2': 'dacxi',
            '0x0a907b0bbff60702b29a36b19718d99253cfbd9f': 'qlix',
            '0x716bb5e0839451068885250442a5b8377f582933': 'fofar0x71',
            '0x13e4b8cffe704d3de6f19e52b201d92c21ec18bd': 'parallelai',
            '0xfb19075d77a0f111796fb259819830f4780f1429': 'fenerbahce-token',
            '0xa1aa371e450c5aee7fff259cbf5cca9384227272': 'pentagon-chain',
            '0xf2a22b900dde3ba18ec2aef67d4c8c1a0dab6aac': 'monkeys',
            '0x70e36f6bf80a52b3b46b3af8e106cc0ed743e8e4': 'ccomp',
            '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0': 'wrapped-steth',
            '0x690031313d70c2545357f4487c6a3f134c434507': 'qqq6900',
            '0x69420cb71f5fa439a84545e79557977c0600c46e': 'trumpeffect69420',
            '0xdc9cb148ecb70876db0abeb92f515a5e1dc9f580': 'green-bitcoin',
            '0x8c1bed5b9a0928467c9b1341da1d7bd5e10b6549': 'liquid-staked-ethereum',
            '0x8ce9137d39326ad0cd6491fb5cc0cba0e089b6a9': 'swipe',
            '0x7e4c9923fd8f18442532a737365c1bfb52579d2f': 'arcadiaos',
            '0xc71b5f631354be6853efe9c3ab6b9590f8302e81': 'polyhedra-network',
            '0xe4b4c008ff36e3c50c4299c223504a480de9c833': 'secret-society',
            '0x164f12c8d7d16b905cc4f11e819a9fc5b183ef71': 'dmarketplace',
            '0xfc21540d6b89667d167d42086e1feb04da3e9b21': 'infinite-2',
            '0xdf87270e04bc5ac140e93571d0dd0c6f4a058b41': 'moolahverse',
            '0x5027fc44a7ba114b8f494b1e4970900c6652fedf': 'arcana-token',
            '0xbf358f7023d6fd0d11ac284eb47b877c1af635aa': 'archeriumai',
            '0xb624960aaad05d433075a5c9e760adec26036934': 'monke-coin-eth',
            '0x30ae41d5f9988d359c733232c6c693c0e645c77e': 'wrapped-ayeayecoin',
            '0x07040971246a73ebda9cf29ea1306bb47c7c4e76': 'american-pepe',
            '0x8f693ca8d21b157107184d29d398a8d082b38b76': 'streamr',
            '0x7316d973b0269863bbfed87302e11334e25ea565': 'ken',
            '0x0018d5e01e53878f90feab02f1b2019a21adf8b1': 'shadowcats',
            '0x6368e1e18c4c419ddfc608a0bed1ccb87b9250fc': 'tap',
            '0x115ec79f1de567ec68b7ae7eda501b406626478e': 'carry',
            '0x48d41fc014865c32be82c50ee647b6a4bfab38a8': 'kumaneene',
            '0x5b7533812759b45c2b44c19e320ba2cd2681b542': 'singularitynet',
            '0x27c78a7c10a0673c3509ccf63044aab92e09edac': 'butterfly-ai',
            '0xfab13732ae25267a5f47f6f31660c9a82b5fa9f1': 'skibidi-dop-dop',
            '0x901a020915bc3577d85d29f68024b4c5e240b8cd': 'blastup',
            '0x243cacb4d5ff6814ad668c3e225246efa886ad5a': 'shina-inu',
            '0x4ad434b8cdc3aa5ac97932d6bd18b5d313ab0f6f': 'evermoon-erc',
            '0xb939da54f9748440a1b279d42be1296942732288': 'fonzy',
            '0x19f78a898f3e3c2f40c6e0cd2ee5545f549d5e99': 'deputy-dawgs',
            '0xcab254f1a32343f11ab41fbde90ecb410cde348a': 'frogevip',
            '0x53206bf5b6b8872c1bb0b3c533e06fde2f7e22e4': 'blepe',
            '0x404d3295c8b1c61662068db584125a7ebcc0d651': 'mambo',
            '0xedc3be0080f65c628964f44ba3f2b6057e60f8dc': 'dash-2',
            '0x9727eaf447203be268e5d471b6503bf47a71ea72': 'arky',
            '0x58d97b57bb95320f9a05dc918aef65434969c2b2': 'morpho',
            '0x2fb652314c3d850e9049057bbe9813f1eee882d3': 'rocketx',
            '0x71fc1f555a39e0b698653ab0b475488ec3c34d57': 'rainmaker-games',
            '0xbdc7c08592ee4aa51d06c27ee23d5087d65adbcd': 'lift-dollar',
            '0xed0439eacf4c4965ae4613d77a5c2efe10e5f183': 'shroom-finance',
            '0xcff252a3299be44fa73402966f30a0159308b2ad': 'envoy-a-i',
            '0x809b05ff167c7d70425951753bc0eb0fcc8e491f': 'callofmeme',
            '0x0f71b8de197a1c84d31de0f1fa7926c365f052b3': 'arcona',
            '0xd4e245848d6e1220dbe62e155d89fa327e43cb06': 'aave-v3-frax',
            '0x283d480dfd6921055e9c335fc177bf8cb9c94184': 'vix777',
            '0x766d2fcece1e3eef32aae8711ab886ee95fd5b2a': 'maga-vp',
            '0x3e43efbfa058d351a926fc611e997f2338adc2a4': 'origent-ai',
            '0x2f5fa8adf5f09a5f9de05b65fe82a404913f02c4': 'troll-2-0',
            '0x15b543e986b8c34074dfc9901136d9355a537e7e': 'student-coin',
            '0xa02c49da76a085e4e1ee60a6b920ddbc8db599f4': 'shiba-inu-treat',
            '0x0026dfbd8dbb6f8d0c88303cc1b1596409fda542': 'sanshu',
            '0x6f40d4a6237c257fff2db00fa0510deeecd303eb': 'instadapp',
            '0x445bd590a01fe6709d4f13a8f579c1e4846921db': 'dummy',
            '0x5d3a536e4d6dbd6114cc1ead35777bab948e3643': 'cdai',
            '0xadd39272e83895e7d3f244f696b7a25635f34234': 'pepe-unchained',
            '0x777172d858dc1599914a1c4c6c9fc48c99a60990': 'solidlydex',
            '0x68449870eea84453044bd430822827e21fd8f101': 'zaibot',
            '0xd528cf2e081f72908e086f8800977df826b5a483': 'paribus',
            '0x5b1d655c93185b06b00f7925791106132cb3ad75': 'darkmatter',
            '0xfa63503f9e61fd59cbea137c122fa55c2daff14a': 'litas',
            '0xcf9560b9e952b195d408be966e4f6cf4ab8206e5': 'doctor-evil',
            '0x94a21565c923d2f75b3fcef158960a8b7e6ed07d': 'merchminter',
            '0x4f311c430540db1d64e635eb55f969f1660b2016': 'pepe-chain-2',
            '0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb': 'ether-fi',
            '0x6942040b6d25d6207e98f8e26c6101755d67ac89': 'mellow-man',
            '0x033bbde722ea3cdcec73cffea6581df9f9c257de': 'velar',
            '0xccc8cb5229b0ac8069c51fd58367fd1e622afd97': 'gods-unchained',
            '0xf9902edfca4f49dcaebc335c73aebd82c79c2886': 'ado-network',
            '0x2b591e99afe9f32eaa6214f7b7629768c40eeb39': 'hex',
            '0xc9eb61ffb66d5815d643bbb8195e17c49687ae1e': 'morpheus-labs',
            '0xe60779cc1b2c1d0580611c526a8df0e3f870ec48': 'unsheth',
            '0xe5b826ca2ca02f09c1725e9bd98d9a8874c30532': 'zeon',
            '0xc28eb2250d1ae32c7e74cfb6d6b86afc9beb6509': 'open-ticketing-ecosystem',
            '0xddbcdd8637d5cedd15eeee398108fca05a71b32b': 'cryptify-ai',
            '0x32b86b99441480a7e5bd3a26c124ec2373e3f015': 'bad-idea-ai',
            '0x0b0a8c7c34374c1d0c649917a97eee6c6c929b1b': 'shiba-v-pepe',
            '0xd502f487e1841fdc805130e13eae80c61186bc98': 'integral',
            '0x46305b2ebcd92809d5fcef577c20c28a185af03c': 'shadowladys-dn404',
            '0x4fe83213d56308330ec302a8bd641f1d0113a4cc': 'nucypher',
            '0xb624fde1a972b1c89ec1dad691442d5e8e891469': 'sporkdao',
            '0xdae0fafd65385e7775cf75b1398735155ef6acd2': 'truth',
            '0x661013bb8d1c95d86d9c85f76e9004561f1bb36f': 'defi-robot',
            '0xd843713a7e6b3627cca4e7f70d34318d72708152': 'furo',
            '0x6d06426a477200c385843a9ac4d4fd55346f2b7b': 'ginnan-neko',
            '0x990f341946a3fdb507ae7e52d17851b87168017c': 'strong',
            '0x80795a7bb55f003b1572411a271e31f73e03dd73': 'daumenfrosch-2',
            '0xf9fb4ad91812b704ba883b11d2b576e890a6730a': 'aave-amm-weth',
            '0x00869e8e2e0343edd11314e6ccb0d78d51547ee5': 'supergrok',
            '0xbddc20ed7978b7d59ef190962f441cd18c14e19f': 'crypto-asset-governance-alliance',
            '0x2da719db753dfa10a62e140f436e1d67f2ddb0d6': 'cere-network',
            '0x9cf0ed013e67db12ca3af8e7506fe401aa14dad6': 'spectre-ai',
            '0xd3fd63209fa2d55b07a0f6db36c2f43900be3094': 'wrapped-savings-rusd',
            '0xd85a6ae55a7f33b0ee113c234d2ee308edeaf7fd': 'cobak-token',
            '0x6e9730ecffbed43fd876a264c982e254ef05a0de': 'nord-finance',
            '0x0f7dc5d02cc1e1f5ee47854d534d332a1081ccc8': 'pepes-dog',
            '0x362033a25b37603d4c99442501fa7b2852ddb435': 'matrix-3',
            '0x378e1be15be6d6d1f23cfe7090b6a77660dbf14d': 'foxe',
            '0xcb69e5750f8dc3b69647b9d8b1f45466ace0a027': 'xiaobai',
            '0xf7554eac0bf20d702e69d08c425e817abb976aea': 'make-america-healthy-again',
            '0xa5c45d48d36607741e90c0cca29545a46f5ee121': 'chiba-wan',
            '0xce872db165d4f5623af9c29e03afd416bc5f67bc': 'stakevault-network',
            '0x5a666c7d92e5fa7edcb6390e4efd6d0cdd69cf37': 'unmarshal',
            '0xa1e349fac47e50b42cd323c4285ef4622b60a5e0': 'pepy-coin',
            '0xb5c5fc6d3576ae31b24dc18e5bcb8a4822f13333': 'whaleai',
            '0xd88611a629265c9af294ffdd2e7fa4546612273e': 'mpro-lab',
            '0x9d1a74967eca155782edf8e84782c74db33fc499': 'ai-com',
            '0x808688c820ab080a6ff1019f03e5ec227d9b522b': 'bag',
            '0x450e7f6e3a2f247a51b98c39297a9a5bfbdb3170': 'elon-goat',
            '0xb87b96868644d99cc70a8565ba7311482edebf6e': 'onchain-pepe-404',
            '0xd1b5651e55d4ceed36251c61c50c889b36f6abb5': 'stake-dao-crv',
            '0x8e0fe2947752be0d5acf73aae77362daf79cb379': 'nftrade',
            '0xe79031b5aaeb3ee8d0145e3d75b81b36bffe341d': 'boppy-the-bat',
            '0x5caf454ba92e6f2c929df14667ee360ed9fd5b26': 'dev-protocol',
            '0x5de597849cf72c72f073e9085bdd0dadd8e6c199': 'finblox',
            '0xf4172630a656a47ece8616e75791290446fa41a0': 'peppa',
            '0x1cc7047e15825f639e0752eb1b89e4225f5327f2': 'pullix',
            '0x6fd46112c8ec76e7940dbfdc150774ee6eff27b2': 'runner-on-eth',
            '0xc06caead870d3a8af2504637b6c5b7248bed6116': 'business-coin',
            '0x1a57367c6194199e5d9aea1ce027431682dfb411': 'matrixetf',
            '0x4dfae3690b93c47470b03036a17b23c1be05127c': 'pepe-2',
            '0x65b3f4a4694b125ada8f9ebc2b79d6c7d4015d1b': 'steam22',
            '0xfc60fc0145d7330e5abcfc52af7b043a1ce18e7d': 'gvnr',
            '0xbef26bd568e421d6708cca55ad6e35f8bfa0c406': 'bitscrunch-token',
            '0xab93df617f51e1e415b5b4f8111f122d6b48e55c': 'delta-exchange-token',
            '0xa21af1050f7b26e0cff45ee51548254c41ed6b5c': 'osaka-protocol',
            '0xf4d861575ecc9493420a3f5a14f85b13f0b50eb3': 'fractal',
            '0x71fc860f7d3a592a4a98740e39db31d25db65ae8': 'aave-usdt-v1',
            '0xbe92b510007bd3ec0adb3d1fca338dd631e98de7': 'degenstogether',
            '0xbb126042235e6bd38b17744cb31a8bf4a206c045': 'fanc',
            '0xb0ffa8000886e57f86dd5264b9582b2ad87b2b91': 'wormhole',
            '0x66d79b8f60ec93bfce0b56f5ac14a2714e509a99': 'marcopolo',
            '0x1776b223ff636d0d76adf2290821f176421dd889': 'america1776',
            '0xfe2e637202056d30016725477c5da089ab0a043a': 'seth2',
            '0x80810a9c31e7243a0bfb9919b0b4020378d1c134': 'the-republican-party',
            '0xd721706581d97ecd202bbab5c71b5a85f0f78e69': 'doge-1',
            '0x249e38ea4102d0cf8264d3701f1a0e39c4f2dc3b': 'ufo-gaming',
            '0x4cd0c43b0d53bc318cc5342b77eb6f124e47f526': 'freerossdao',
            '0xa8b12cc90abf65191532a12bb5394a714a46d358': 'pbtc35a',
            '0x48c276e8d03813224bb1e55f953adb6d02fd3e02': 'kuma-inu',
            '0x8dd09822e83313adca54c75696ae80c5429697ff': 'sifu-vision-2',
            '0x2a414884a549ef5716bc1a4e648d3dc03f08b2cf': 'perq',
            '0xd1f2586790a5bd6da1e443441df53af6ec213d83': 'ledger-ai',
            '0x98968f0747e0a261532cacc0be296375f5c08398': 'mooncat-vault-nftx',
            '0x04c154b66cb340f3ae24111cc767e0184ed00cc6': 'dinero-staked-eth',
            '0x420b879b0d18cc182e7e82ad16a13877c3a88420': 'big-bud',
            '0x005e6fd1610302018dcd9caf29b8bc38ff6efd98': 'metafox',
            '0x40e5a14e1d151f34fea6b8e6197c338e737f9bf2': 'valinity',
            '0x391cf4b21f557c935c7f670218ef42c21bd8d686': 'morphware',
            '0xe1c8d908f0e495cf6d8459547d1d28b72bf04bf2': 'tesseractai',
            '0xc67b12049c2d0cf6e476bc64c7f82fc6c63cffc5': 'globe-derivative-exchange',
            '0xeeb4d8400aeefafc1b2953e0094134a887c76bd8': 'avail',
            '0x2596825a84888e8f24b747df29e11b5dd03c81d7': 'faith-tribe',
            '0x69cbaf6c147086c3c234385556f8a0c6488d3420': '69420',
            '0xe1d7c7a4596b038ced2a84bf65b8647271c53208': 'nfty-token',
            '0x91fbb2503ac69702061f1ac6885759fc853e6eae': 'k9-finance-dao',
            '0x108a850856db3f85d0269a2693d896b394c80325': 'thorwallet',
            '0x21cd589a989615a9e901328d3c089bbca16d00b2': 'x-money',
            '0x4a467232abe1472f9abeb49dcd2b34590222cae9': 'grid-protocol',
            '0xc114d80a2a188f30400b3cd545c5e296f0b04c3f': 'rita-elite-order',
            '0xa92e7c82b11d10716ab534051b271d2f6aef7df5': 'ara-token',
            '0xabd4c63d2616a5201454168269031355f4764337': 'orderly-network',
            '0x69bb12b8ee418e4833b8debe4a2bb997ab9ce18e': 'mohameme-bit-salman',
            '0x807534b396919783b7e30383fe57d857bc084338': 'test-2',
            '0x57b96d4af698605563a4653d882635da59bf11af': 'rch-token',
            '0xf938346d7117534222b48d09325a6b8162b3a9e7': 'choppy',
            '0x798bcb35d2d48c8ce7ef8171860b8d53a98b361d': 'meta-pool',
            '0xa562912e1328eea987e04c2650efb5703757850c': 'drops',
            '0x055999b83f9cade9e3988a0f34ef72817566800d': 'bbs-network',
            '0x24c19f7101c1731b85f1127eaa0407732e36ecdd': 'sharedstake-governance-token',
            '0xf4c0efc13ea4221ad8278fb53727015471dce938': 'sp500-token',
            '0xcccccccccc33d538dbc2ee4feab0a7a1ff4e8a94': 'centrifuge-2',
            '0xf6ce4be313ead51511215f1874c898239a331e37': 'bird-dog',
            '0x590830dfdf9a3f68afcdde2694773debdf267774': 'giza',
            '0x525536d71848f21b66da0d239546c50ee4c1a358': 'crypto-task-force',
            '0xf3e66b03d098d0482be9cb3d6999787231a93ed9': 'promptide',
            '0x2ef52ed7de8c5ce03a4ef0efbe9b7450f2d7edc9': 'revain',
            '0x4168bbc34baea34e55721809911bca5baaef6ba6': 'dodreamchain',
            '0x9e10f61749c4952c320412a6b26901605ff6da1d': 'theos',
            '0x2efa572467c50c04a6eed6742196c0d0d287c1bb': 'based-chad',
            '0xde4ee8057785a7e8e800db58f9784845a5c2cbd6': 'dexe',
            '0x50d5118fb90d572b9d42ba65e0addc4900867809': 'osean',
            '0x8a7b7b9b2f7d0c63f66171721339705a6188a7d5': 'etherdoge',
            '0x7eeab3de47a475fd2dec438aef05b128887c6105': 'troppy',
            '0xe53ec727dbdeb9e2d5456c3be40cff031ab40a55': 'superfarm',
            '0x2b37127988e4e5e9576b7a533d873c23cfbdb1e9': 'zentium-tech',
            '0x038a68ff68c393373ec894015816e33ad41bd564': 'glitch-protocol',
            '0x1b3be8fcd2e7c5ce9c5c242e0066fdd9740220d0': 'licker',
            '0x522ec96bced6dc26325120edf3931d34e417a620': 'market-stalker',
            '0x22b6c31c2beb8f2d0d5373146eed41ab9ede3caf': 'cocktailbar',
            '0x7c1156e515aa1a2e851674120074968c905aaf37': 'level-usd',
            '0xbe0ed4138121ecfc5c0e56b40517da27e6c5226b': 'aethir',
            '0x85eee30c52b0b379b046fb0f85f4f3dc3009afec': 'keep-network',
            '0x7a4effd87c2f3c55ca251080b1343b605f327e3a': 'restaking-vault-eth',
            '0xf2dfdbe1ea71bbdcb5a4662a16dbf5e487be3ebe': 'decloud',
            '0x3bb1be077f3f96722ae92ec985ab37fd0a0c4c51': 'marv',
            '0x1010107b4757c915bc2f1ecd08c85d1bb0be92e0': 'brain-frog',
            '0x33e07f5055173cf8febede8b21b12d1e2b523205': 'etherland',
            '0x149af500734056b98572b66e6c771e57408e12e4': 'horizon-4',
            '0x668c50b1c7f46effbe3f242687071d7908aab00a': 'coshi-inu',
            '0x3850952491606a0e420eb929b1a2e1a450d013f1': 'panoverse',
            '0xd2bdaaf2b9cc6981fd273dcb7c04023bfbe0a7fe': 'aviator',
            '0x39fbbabf11738317a448031930706cd3e612e1b9': 'wrapped-xrp',
            '0x8c6bf16c273636523c29db7db04396143770f6a0': 'moon-rabbit',
            '0x77146784315ba81904d654466968e3a7c196d1f3': 'treehouse',
            '0xbabe3ce7835665464228df00b03246115c30730a': 'baby-neiro-token',
            '0x06b964d96f5dcf7eae9d7c559b09edce244d4b8e': 'usualx',
            '0xd69a0a9682f679f50e34de40105a93bebb2ff43d': 'mackerel-2',
            '0x42069f39c71816cea208451598425b492dd2b380': 'goompy',
            '0xb6ca7399b4f9ca56fc27cbff44f4d2e4eef1fc81': 'muse-2',
            '0x320ed4c7243e35a00f9ca30a1ae60929d15eae37': 'the-blox-project',
            '0xfcf7985661d2c3f62208970cbe25e70bcce73e7c': 'rwa-ai',
            '0xe5097d9baeafb89f9bcb78c9290d545db5f9e9cb': 'hummingbot',
            '0xaa4e3edb11afa93c41db59842b29de64b72e355b': 'marginswap',
            '0xdc300854b0ef52650057158e8a33afe703525539': 'betmore-casino',
            '0x3073f7aaa4db83f95e9fff17424f71d4751a3073': 'movement',
            '0xd888a5460fffa4b14340dd9fe2710cbabd520659': 'protokols',
            '0x34df29dd880e9fe2cec0f85f7658b75606fb2870': 'navy-seal',
            '0x7c84e62859d0715eb77d1b1c4154ecd6abb21bec': 'shping',
            '0x6c6ee5e31d828de241282b9606c8e98ea48526e2': 'holotoken',
            '0xb62132e35a6c13ee1ee0f84dc5d40bad8d815206': 'nexo',
            '0x464ebe77c293e473b48cfe96ddcf88fcf7bfdac0': 'kryll',
            '0x8400d94a5cb0fa0d041a3788e395285d61c9ee5e': 'unibright',
            '0xea26c4ac16d4a5a106820bc8aee85fd0b7b2b664': 'quark-chain',
            '0xa849eaae994fb86afa73382e9bd88c2b6b18dc71': 'mass-vehicle-ledger',
            '0xd26114cd6ee289accf82350c8d8487fedb8a0c07': 'omisego',
            '0xb8c77482e45f1f44de1745f52c74426c631bdd52': 'binancecoin',
            '0x5d60d8d7ef6d37e16ebabc324de3be57f135e0bc': 'mybit-token',
            '0x0f8c45b896784a1e408526b9300519ef8660209c': 'xmax',
            '0x4e15361fd6b4bb609fa63c81a2be19d873717870': 'wrapped-fantom',
            '0xdd16ec0f66e54d453e6756713e533355989040e4': 'tokenomy',
            '0x814e0908b12a99fecf5bc101bb5d0b8b5cdf7d26': 'measurable-data-token',
            '0x846c66cf71c43f80403b51fe3906b3599d63336f': 'pumapay',
            '0x4a220e6096b25eadb88358cb44068a3248254675': 'quant-network',
            '0xa15c7ebe1f07caf6bff097d8a589fb8ac49ae5b3': 'pundi-x',
            '0x509a38b7a1cc0dcd83aa9d06214663d9ec7c7f4a': 'blocksquare',
            '0xdf2c7238198ad8b389666574f2d8bc411a4b7428': 'mainframe',
            '0xfc05987bd2be489accf0f509e44b0145d68240f7': 'essentia',
            '0x93ed3fbe21207ec2e8f2d3c3de6e058cb73bc04d': 'kleros',
            '0x986ee2b944c42d017f52af21c4c69b84dbea35d8': 'bitmart-token',
            '0xc719d010b63e5bbf2c0551872cd5316ed26acd83': 'etherisc',
            '0x765f0c16d1ddc279295c1a7c24b0883f62d33f75': 'databroker-dao',
            '0xe50365f5d679cb98a1dd62d6f6e58e59321bcddf': 'latoken',
            '0xc64500dd7b0f1794807e67802f8abbf5f8ffb054': 'locus-chain',
            '0xff56cc6b1e6ded347aa0b7676c85ab0b3d08b0fa': 'orbs',
            '0xdac17f958d2ee523a2206206994597c13d831ec7': 'tether',
            '0x8f3470a7388c05ee4e7af3d01d8c722b0ff52374': 'veritaseum',
            '0xef53462838000184f35f7d991452e5f25110b207': 'knit-finance',
            '0xd47bdf574b4f76210ed503e0efe81b58aa061f3d': 'dtravel',
            '0x8e57c27761ebbd381b0f9d09bb92ceb51a358abb': 'extradna',
            '0x295b42684f90c77da7ea46336001010f2791ec8c': 'xi-token',
            '0xfe9a29ab92522d14fc65880d817214261d8479ae': 'snowswap',
            '0xcbd55d4ffc43467142761a764763652b48b969ff': 'astrotools',
            '0xf1f508c7c9f0d1b15a76fba564eef2d956220cf7': 'pepedex',
            '0x5cb3ce6d081fb00d5f6677d196f2d70010ea3f4a': 'busy-dao',
            '0xca9b8d6df0729d85dcfc8ef8bb18af1ad1990786': 'catboy-3',
            '0x5845684b49aef79a5c0f887f50401c247dca7ac6': 'cycle-2',
            '0x6985884c4392d348587b19cb9eaaf157f13271cd': 'layerzero',
            '0xa41f142b6eb2b164f8164cae0716892ce02f311f': 'avaocado-dao',
            '0x59f4f336bf3d0c49dbfba4a74ebd2a6ace40539a': 'catcoin-cash',
            '0xa2e3356610840701bdf5611a53974510ae27e2e1': 'wrapped-beacon-eth',
            '0x22514ffb0d7232a56f0c24090e7b68f179faa940': 'qopro',
            '0x9840652dc04fb9db2c43853633f0f62be6f00f98': 'chaingpt',
            '0xd48d639f72ef29458b72cdc9a47a95fa46101529': 'helpkidz-coin',
            '0xdc49a53e1f15fd7fd522e0691cb570f442e9ca6c': 'quorium',
            '0x124123c7af9efd2a86f4d41daa88ac164d02a3d5': 'greenenvironmentalcoins',
            '0x35de111558f691f77f791fb0c08b2d6b931a9d47': 'chain-games',
            '0x193f4a4a6ea24102f49b931deeeb931f6e32405d': 'telos',
            '0x36f1f32c728c3f330409ec1f0928fa3ab3c8a76f': 'adroverse',
            '0x551faab1027cc50efaea5bed092e330475c3cd99': 'monbasecoin',
            '0x6067490d05f3cf2fdffc0e353b1f5fd6e5ccdf70': 'market-making-pro',
            '0xc58c1117da964aebe91fef88f6f5703e79bda574': 'telebtc-2',
            '0x4ff1f7ee6516dd1d14db83c2cbce06b69ad14444': 'memecoin1',
            '0x261510dd6257494eea1dda7618dbe8a7b87870dd': 'dehero-community-token',
            '0x29132062319aa375e764ef8ef756f2b28c77a9c9': 'blokpad',
            '0x32d7da6a7cf25ed1b86e1b0ee9a62b0252d46b16': 'ginza-network',
            '0x9d0d41df4ca809dc16a9bff646d3c6cbc4ebc707': 'rezor',
            '0xb1957bdba889686ebde631df970ece6a7571a1b6': 'defi-tiger',
            '0x999e62f80d2c8ec8adfbf041b06239c6ae6d8492': 'roomcon',
            '0x5392ff4a9bd006dc272c1855af6640e17cc5ec0b': 'safelaunch',
            '0x9b208b117b2c4f76c1534b6f006b033220a681a4': 'dingocoin',
            '0xe00e6919895929090c2d5342ae8375c169cf8888': 'binants',
            '0x551897f8203bd131b350601d3ac0679ba0fc0136': 'nfprompt-token',
            '0x4db5a66e937a9f4473fa95b1caf1d1e1d62e29ea': 'ethereum-wormhole',
            '0x6ec90334d89dbdc89e08a133271be3d104128edb': 'wiki-cat',
            '0x963556de0eb8138e97a85f0a86ee0acd159d210b': 'melega',
            '0x8a74bc8c372bc7f0e9ca3f6ac0df51be15aec47a': 'pulsepad',
            '0x84f4f7cdb4574c9556a494dab18ffc1d1d22316c': 'king-shiba',
            '0x3fefe29da25bea166fb5f6ade7b5976d2b0e586b': 'roam-token',
            '0xfd42728b76772a82ccad527e298dd15a55f4ddd6': 'karencoin',
            '0x94a8b4ee5cd64c79d0ee816f467ea73009f51aa0': 'realio-network',
            '0x12819623921be0f4d5ebfc12c75e6d08a1683080': 'broccoli-2',
            '0xc08cd26474722ce93f4d0c34d16201461c10aa8c': 'carv',
            '0x9a26e6d24df036b0b015016d1b55011c19e76c87': 'dragon-mainland-shards',
            '0xc350caa89eb963d5d6b964324a0a7736d8d65533': 'infinitee',
            '0x968f6f898a6df937fc1859b323ac2f14643e3fed': 'newscrypto-coin',
            '0xbb1b031c591235408755ff4e0739cb88c5cf2507': 'paal-ai',
            '0x3ef144cb45c8a390eb207a6aa9bfcf3da639cb5c': 'maga-coin',
            '0x72a76965eb8f606675f119dae89deda557fdbf01': 'eiqt-token',
            '0x8fb238058e71f828f505582e65b1d14f8cf52067': 'dar-open-network',
            '0x2442421fe1acc8a732251fc372892b5ff1fdd938': 'deer-token',
            '0x6ccc8db8e3fd5ffdd2e7b92bd92e8e27baf704a8': 'ethos-2',
            '0xb003c68917bab76812797d1b8056822f48e2e4fe': 'yummy',
            '0x69df2aaea7a40dad19c74e65192df0d0f7f7912b': 'alita-2',
            '0x4e93bfcd6378e564c454bf99e130ae10a1c7b2dd': 'airbtc',
            '0xd9e90df21f4229249e8841580cde7048bf935710': 'shield-protocol-3',
            '0xdfa7e9c060dc5292c881eb48cfe26b27aef5f0d9': 'bnbgpt',
            '0x0e7779e698052f8fe56c415c3818fcf89de9ac6d': 'ultiverse',
            '0x40f85d6040df96ea14cd41142bcd244e14cf76f6': 'usd-coin-bridged-zed20',
            '0xeee352f77f28d31601eb20d3de09d7729ca2dc79': 'austin-capitals',
            '0x841c1297f5485ecd72e7a9b62de5ef19f81c8af3': 'dpin',
            '0xa90298e5b1203a2dd0006a75eabe158989c406fb': 'blue-protocol',
            '0x6b85f1fe36af537ce5085ef441c92de09af74f0e': 'robotic-doge',
            '0x25382fb31e4b22e0ea09cb0761863df5ad97ed72': 'paragen',
            '0x61ec85ab89377db65762e234c946b5c25a56e99e': 'htx-dao',
            '0xa14b0b99c9117ea2f4fb2c9d772d95d9fd3acaab': 'broccoli-5',
            '0x9158df7da69b048a296636d5de7a3d9a7fb25e88': 'kalijo',
            '0x4ea98c1999575aaadfb38237dd015c5e773f75a2': 'maga',
            '0x6fd2854cd1b05b8eb5f6d25c714184a92fedaf4f': 'o-megax',
            '0xee7e8c85956d32c64bafdcded3f43b3c39b1ce2f': 'web4-ai',
            '0x6685906b75c61c57772c335402f594f855c1b0e3': 'wilder-world',
            '0x053708a5bc7f1627ddc87e780ee381cf1e31f765': 'vela-ai',
            '0x66207e39bb77e6b99aab56795c7c340c08520d83': 'rupiah-token',
            '0x3b0e967ce7712ec68131a809db4f78ce9490e779': 'souni-token',
            '0x6ec9a568881755c9698384cc6b5b13bf4064e12b': 'optimus-x',
            '0xa0cb0ce7c6d93a7ebd72952feb4407dddee8a194': 'shibaken-finance',
            '0x5f320c3b8f82acfe8f2bb1c85d63aa66a7ff524f': 'nelore-coin',
            '0x1bec41a36356d5574aeb068b599ab7e48dd008b8': 'dogefood',
            '0xd89336eac00e689d218c46cdd854585a09f432b3': 'lusd-2',
            '0x9cd9c5a44cb8fab39b2ee3556f5c439e65e4fddd': 'mars4',
            '0xb01cf1be9568f09449382a47cd5bf58e2a9d5922': 'lightspeed',
            '0xffffff9936bd58a008855b0812b44d2c8dffe2aa': 'good-game-us-dollar',
            '0xc9d23ed2adb0f551369946bd377f8644ce1ca5c4': 'hyperlane',
            '0xe215f9575e2fafff8d0d3f9c6866ac656bd25bd9': 'ducky-2',
            '0x7c1941e49e388daf3d75ec2d187d49eca86392ea': 'licko-2',
            '0x07c15e4add8c23d2971380dde6c57b6f88902ec1': 'metamars-2',
            '0x347862372f7c8f83d69025234367ac11c5241db3': 'kiirocoin',
            '0xf2b688b2201979d44fdf18d1d8c641305cf560ba': 'devomon',
            '0xf9752a6e8a5e5f5e6eb3ab4e7d8492460fb319f0': 'ares-protocol',
            '0x7f14ce2a5df31ad0d2bf658d3840b1f7559d3ee0': 'nfstay',
            '0xbb0fa2fbe9b37444f5d1dbd22e0e5bdd2afbbe85': 'usd-mars',
            '0xb700597d8425ced17677bc68042d7d92764acf59': 'facedao',
            '0xe138c66982fd5c890c60b94fdba1747faf092c20': 'offshift',
            '0xac83271abb4ec95386f08ad2b904a46c61777cef': 'nftrade',
            '0xf2c88757f8d03634671208935974b60a2a28bdb3': 'myshell',
            '0x633237c6fa30fae46cc5bb22014da30e50a718cc': 'defi-warrior',
            '0x90869b3a42e399951bd5f5ff278b8cc5ee1dc0fe': 'revox',
            '0x537be31d47fbb697b36a098932cfc1343ac5f538': 'baby-rudi',
            '0x2598c30330d5771ae9f983979209486ae26de875': 'any-inu',
            '0x9c27c4072738cf4b7b0b7071af0ad5666bddc096': 'nianian',
            '0x7b4bf9feccff207ef2cb7101ceb15b8516021acd': 'milkyway-2',
            '0x8888888809b788cd6e40a2d27e67425d5d0b5d3b': 'changcoin',
            '0xa18bbdcd86e4178d10ecd9316667cfe4c4aa8717': 'bnbxbt',
            '0x34ba3af693d6c776d73c7fa67e2b2e79be8ef4ed': 'shambala',
            '0xcf10117b30c7a5fc7c77b611bfc2555610dd4b3a': 'notai',
            '0xcd883a18f8d33cf823d13cf2c6787c913d09e640': 'talentido',
            '0x3e2242cb2fc1465822a0bb81ca2fe1f633a45757': 'forky-2',
            '0x722294f6c97102fb0ddb5b907c8d16bdeab3f6d9': 'doodles',
            '0x8ea5219a16c2dbf1d6335a6aa0c6bd45c50347c5': 'openocean',
            '0x8b4c03308579a0c4166b44f84565d97378303247': 'madonna-del-gatto',
            '0x7f792db54b0e580cdc755178443f0430cf799aca': 'volt-inu-2',
            '0x518445f0db93863e5e93a7f70617c05afa8048f1': 'bittoken',
            '0x19be6f3f83d079d640720bda3b638a00a3b7ee20': 'kitnet-token',
            '0x1236a887ef31b4d32e1f0a2b5e4531f52cec7e75': 'gami-world',
            '0xcbd9f6d748dd3d19416f8914528a65c7838e27d8': 'r-games',
            '0x2a17dc11a1828725cdb318e0036acf12727d27a2': 'arena-token',
            '0x921d3a6ed8223afb6358410f717e2fb13cbae700': 'qrkita-token',
            '0x4027d91ecd3140e53ae743d657549adfeebb27ab': 'chain-of-legends',
            '0x5651fa7a726b9ec0cad00ee140179912b6e73599': 'oort',
            '0x55ad16bd573b3365f43a9daeb0cc66a73821b4a5': 'okzoo',
            '0x1894251aebcff227133575ed3069be9670e25db0': 'halo-coin',
            '0x4823a096382f4fa583b55d563afb9f9a58c72fc0': 'arabic',
            '0xa856098dcbc1b2b3a9c96c35c32bc4f71e49aed2': 'finceptor-token',
            '0xe4e11e02aa14c7f24db749421986eaec1369e8c9': 'minativerse',
            '0xe3f53c0d48360de764ddc2a1a82c3e6db5d4624d': 'emoneytoken',
            '0x502a641decfe32b1e3d030e05effb8ae5146e64b': 'palm-economy',
            '0x07b36f2549291d320132712a1e64d3826b1fb4d7': 'wifedoge',
            '0xa53e61578ff54f1ad70186be99332a6e20b6ffa9': 'golden-doge',
            '0x5e57f24415f37c7d304e85df9b4c36bc08789794': 'barter',
            '0x8b9ee39195ea99d6ddd68030f44131116bc218f6': 'peaq-2',
            '0x121235cff4c59eec80b14c1d38b44e7de3a18287': 'darkshield',
            '0xfe2dd2d57a05f89438f3aec94eafa4070396bab0': 'matchain',
            '0xf3f3d7f713df0447e9595d9b830a5f00297070e4': 'mother-earth',
            '0x5b6ebb33eea2d12eefd4a9b2aeaf733231169684': 'weld',
            '0xceb24c99579e6140517d59c8dd4f5b36d84ed6de': 'phecda',
            '0x8182ac1c5512eb67756a89c40fadb2311757bd32': 'nether',
            '0xf39e4b21c84e737df08e2c3b32541d856f508e48': 'yooldo-games',
            '0xd39ba5680e5a59ed032054485a0a8d2d5a6a2366': 'mcoin-2',
            '0x9025daa1fe2d27700187e0eac670818945f94c2e': 'stage',
            '0xc6ec7898b0bdf5ac41fbabdbe19250ca4917c5a6': 'felis',
            '0xa026ad2ceda16ca5fc28fd3c72f99e2c332c8a26': 'xcad-network',
            '0x1cc1aca0dae2d6c4a0e8ae7b4f2d01eabbc435ee': 'stronghands-finance',
            '0xe283d0e3b8c102badf5e8166b73e02d96d92f688': 'elephant-money',
            '0x94db03752342bc9b5bbf89e3bf0132494f0cb2b3': 'dogai',
            '0xe3894cb9e92ca78524fb6a30ff072fa5e533c162': 'the-everlasting-parachain',
            '0x22fffab2e52c4a1dff83b7db7ef319698d48667f': 'bull',
            '0xde914ed9f96853ab95df19481bd14f0fd9dc2249': 'vulpe-finance',
            '0x799a290f9cc4085a0ce5b42b5f2c30193a7a872b': 'elderglade',
            '0xd5d0322b6bab6a762c79f8c81a0b674778e13aed': 'binance-peg-firo',
            '0xa01000c52b234a92563ba61e5649b7c76e1ba0f3': 'rocki',
            '0x4341bb2200176f89eb90eac4fd6cfe958e206005': 'eafin',
            '0x22830be0954ff3bf7929405c488b1bba54a7e0d3': 'brcstarter',
            '0xff7d6a96ae471bbcd7713af9cb1feeb16cf56b41': 'bedrock-token',
            '0x6d57f5c286e04850c2c085350f2e60aaa7b7c15b': 'grok-girl',
            '0x5f39dd1bb6db20f3e792c4489f514794cac6392c': 'playnity',
            '0xaa076b62efc6f357882e07665157a271ab46a063': 'pleasure-coin',
            '0x0ee7292bd28f4a490f849fb30c28cabab9440f9e': 'gemlink',
            '0x2d060ef4d6bf7f9e5edde373ab735513c0e4f944': 'solidus-aitech',
            '0x6ad0b271f4b3d7651ae9947a18bae29ca20d83eb': 'nft-workx',
            '0xa677bc9bdb10329e488a4d8387ed7a08b2fc9005': 'magic-power',
            '0x2167afa1c658dc5c4ec975f4af608ff075a8b8ae': 'evai-2',
            '0x7db13e8b9eaa42fc948268b954dd4e6218cc4cb1': 'fight-win-ai',
            '0xacf34edcc424128cccc730bf85cdaceebcb3eece': 'voice-street',
            '0x44f161ae29361e332dea039dfa2f404e0bc5b5cc': 'humanity',
            '0x8cd0d76c0ad377378ab6ce878a7be686223497ee': 'hydraverse',
            '0xb626213cb1d52caa1ed71e2a0e62c0113ed8d642': 'hughug-coin',
            '0x00f71afe867b2dbd2ad4ba14fd139bc6bc659ccd': 'xoxo-monkey',
            '0xd16cb89f621820bc19dae1c29c9db6d22813b01d': 'coinbidex',
            '0xe6884e29ffe5c6f68f4958cf201b0e308f982ac9': 'vegasino',
            '0x7b665b2f633d9363b89a98b094b1f9e732bd8f86': 'amazy',
            '0xdd325c38b12903b727d16961e61333f4871a70e0': 'elephant-money-trunk',
            '0x679d2c23497d4431311ac001618cd0b8789ac29c': 'linkfi',
            '0x6587eff07d9ae00f05fae2a3a032b2c1a1dfce41': 'freedogs',
            '0x3aa6b9a5306d1cd48b0466cfb130b08a70257e12': 'gorilla-finance',
            '0xfdc66a08b0d0dc44c17bbd471b88f49f50cdd20f': 'smardex',
            '0x374c5fb7979d5fdbaad2d95409e235e5cbdfd43c': 'milk-alliance',
            '0xbd4c4dc19f208cda6caacadadc0bff4cd975fa34': 'dogs-rock',
            '0x68de53b47be0dc566bf4673c748d58bbbad3deb1': 'dogegrow',
            '0x64cf1e2cab86694ac8b31653460faa47a68f59f0': 'gamescoin',
            '0xed00fc7d48b57b81fe65d1ce71c0985e4cf442cb': 'chirpley',
            '0xeb2b7d5691878627eff20492ca7c9a71228d931d': 'crepe-2',
            '0xee81ca267b8357ba30049d679027ebf65fcf7458': 'vopo',
            '0x824a50df33ac1b41afc52f4194e2e8356c17c3ac': 'kick',
            '0x1861c9058577c3b48e73d91d6f25c18b17fbffe0': 'stacktical',
            '0x84c97300a190676a19d1e13115629a11f8482bd1': 'dot-dot-finance',
            '0x945cd29a40629ada610c2f6eba3f393756aa4444': 'usd1doge',
            '0x238950013fa29a3575eb7a3d99c00304047a77b5': 'beeper-coin',
            '0x97b17ac9a0c4bf03cf3b9ed2ee6e397fb319705b': 'bnbull',
            '0x5f113f7ef20ff111fd130e83d8e97fd1e0e2518f': 'aimalls',
            '0x28ce223853d123b52c74439b10b43366d73fd3b5': 'fame-mma',
            '0xf3e07812ebc8604fddb0aa35ff79a03f48f48948': 'journart',
            '0x22b4fa9a13a0d303ad258ee6d62a6ac60364b0c9': 'big-pump',
            '0x3cb20d96e866d128bc469a6e66505d46d7f9baba': 'bib',
            '0x43b35e89d15b91162dea1c51133c4c93bdd1c4af': 'sakai-vault',
            '0x0688977ae5b10075f46519063fd2f03adc052c1f': '5th-scape',
            '0x84fd7cc4cd689fc021ee3d00759b6d255269d538': 'pankuku',
            '0x88691f292b76bf4d2caa5678a54515fae77c33af': 'xpense-2',
            '0xbc33b4d48f76d17a1800afcb730e8a6aaada7fe5': 'voucher-dot',
            '0x18c4af61dbe6fd55d6470943b4ab8530777d009c': 'agatech',
            '0xedd52d44de950ccc3b2e6abdf0da8e99bb0ec480': 'crazy-tiger',
            '0x4f7ea8f6487a7007ca054f35c4a7b961f5b18961': 'goldencat',
            '0x330f4fe5ef44b4d0742fe8bed8ca5e29359870df': 'jade-currency',
            '0xaf41054c1487b0e5e2b9250c0332ecbce6ce9d71': 'ellipsis-x',
            '0x7c3b00cb3b40cc77d88329a58574e29cfa3cb9e2': 'mintstakeshare',
            '0xe6ffa2e574a8bbeb5243d2109b6b11d4a459f88b': 'hippo-token',
            '0x193397bb76868c6873e733ad60d5953843ebc84e': 'memetoon',
            '0xfb62ae373aca027177d1c18ee0862817f9080d08': 'my-defi-pet',
            '0xfb6115445bff7b52feb98650c87f44907e58f802': 'aave',
            '0xfb5b838b6cfeedc2873ab27866079ac55363d37e': 'floki',
            '0xfebe8c1ed424dbf688551d4e2267e7a53698f0aa': 'vita-inu',
            '0xfd5840cd36d94d7229439859c0112a4185bc0255': 'venus-usdt',
            '0xfce146bf3146100cfe5db4129cf6c82b0ef4ad8c': 'renbtc',
            '0xf9cec8d50f6c8ad3fb6dccec577e05aa32b224fe': 'chromaway',
            '0xf859bf77cbe8699013d6dbc7c2b926aaf307f830': 'berry-data',
            '0xf7686f43591302cd9b4b9c4fe1291473fae7d9c9': 'lossless',
            '0xf508fcd89b8bd15579dc79a6827cb4686a3592c8': 'venus-eth',
            '0xf307910a4c7bbc79691fd374889b36d8531b08e3': 'ankr',
            '0xf16e81dce15b08f326220742020379b855b87df9': 'ice-token',
            '0xeca88125a5adbe82614ffc12d0db554e2e2867c8': 'venus-usdc',
            '0xebaffc2d2ea7c66fb848c48124b753f93a0a90ec': 'asia-coin',
            '0xea89199344a492853502a7a699cc4230854451b8': 'oni-token',
            '0xeeeeeb57642040be42185f49c52f7e9b38f8eeee': 'elk-finance',
            '0xed28a457a5a76596ac48d87c0f577020f6ea1c4c': 'ptokens-btc',
            '0xeceb87cf00dcbf2d4e2880223743ff087a995ad9': 'numbers-protocol',
            '0xeb953eda0dc65e3246f43dc8fa13f35623bdd5ed': 'rainicorn',
            '0xe9e7cea3dedca5984780bafc599bd69add087d56': 'binance-peg-busd',
            '0xe91a8d2c584ca93c7405f15c22cdfe53c29896e3': 'dextools',
            '0xe90d1567ecef9282cc1ab348d9e9e2ac95659b99': 'coinxpad',
            '0xe87e15b9c7d989474cb6d8c56b3db4efad5b21e8': 'hokkaidu-inu',
            '0xe80772eaf6e2e18b651f160bc9158b2a5cafca65': 'usd',
            '0xe7c9c6bc87b86f9e5b57072f907ee6460b593924': 'tower',
            '0xe6df05ce8c8301223373cf5b969afcb1498c5528': 'bnb48-club-token',
            '0xe60eaf5a997dfae83739e035b005a33afdcc6df5': 'deri-protocol',
            '0xe2a59d5e33c6540e18aaa46bf98917ac3158db0d': 'purefi',
            '0xe2604c9561d490624aa35e156e65e590eb749519': 'goldminer',
            '0xe20b9e246db5a0d21bf9209e4858bc9a3ff7a034': 'wrapped-banano',
            '0xe0f94ac5462997d2bc57287ac3a3ae4c31345d66': 'ceek',
            '0xe0191fefdd0d2b39b1a2e4e029ccda8a481b7995': 'cryptomines-reborn',
            '0xde3dbbe30cfa9f437b293294d1fd64b26045c71a': 'nftb',
            '0xdaacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92': 'pnetwork',
            '0xdf9e1a85db4f985d5bb5644ad07d9d7ee5673b5e': 'mm72',
            '0xd9780513292477c4039dfda1cfcd89ff111e9da5': 'tegro',
            '0xd9025e25bb6cf39f8c926a704039d2dd51088063': 'coinary-token',
            '0xd88ca08d8eec1e9e09562213ae83a7853ebb5d28': 'xwin-finance',
            '0xd73f32833b6d5d9c8070c23e599e283a3039823c': 'waterfall-governance-token',
            '0xd6fdde76b8c1c45b33790cc8751d5b88984c44ec': 'strikecoin',
            '0xd632bd021a07af70592ce1e18717ab9aa126decb': 'kangal',
            '0xd4fbc57b6233f268e7fba3b66e62719d74deecbc': 'modefi',
            '0xd32d01a43c869edcd1117c640fbdcfcfd97d9d65': 'nominex',
            '0xd21d29b38374528675c34936bf7d5dd693d2a577': 'parsiq',
            '0xcfcecfe2bd2fed07a9145222e8a7ad9cf1ccd22a': 'adshares',
            '0xcaf5191fc480f43e4df80106c7695eca56e48b18': 'deapcoin',
            '0xca830317146bfdde71e7c0b880e2ec1f66e273ee': 'polygod',
            '0xcf6bb5389c92bdda8a3747ddb454cb7a64626c63': 'venus',
            '0xc9457161320210d22f0d0d5fc1309acb383d4609': 'dovu',
            '0xc864019047b864b6ab609a968ae2725dfaee808a': 'biconomy-exchange-token',
            '0xc7981767f644c7f8e483dabdc413e8a371b83079': 'liquidus',
            '0xc748673057861a797275cd8a068abb95a902e8de': 'baby-doge-coin',
            '0xc7091aa18598b87588e37501b6ce865263cd67ce': 'cheesecakeswap',
            '0xc6dddb5bc6e61e0841c54f3e723ae1f3a807260b': 'urus-token',
            '0xc5e6689c9c8b02be7c49912ef19e79cf24977f03': 'alpaca',
            '0xc53708664b99df348dd27c3ac0759d2da9c40462': 'gourmetgalaxy',
            '0xc2e9d07f66a89c44062459a47a0d2dc038e4fb16': 'pstake-staked-bnb',
            '0xba2ae424d960c26247dd6c32edc70b295c744c43': 'binance-peg-dogecoin',
            '0xb86abcb37c3a4b64f74f59301aff131a1becc787': 'zilliqa',
            '0xb6c53431608e626ac81a9776ac3e999c5556717c': 'wrapped-telos',
            '0xb5be8d87fce6ce87a24b90abdb019458a8ec31f9': 'obortech',
            '0xb59490ab09a0f526cc7305822ac65f2ab12f9723': 'litentry',
            '0xb465f3cb6aba6ee375e12918387de1eac2301b05': 'trivian',
            '0xb3a6381070b1a15169dea646166ec0699fdaea79': 'cyberdragon-gold',
            '0xb2ea51baa12c461327d12a2069d47b30e680b69d': 'space-misfits',
            '0xaf6162dc717cfc8818efc8d6f46a41cf7042fcba': 'atlas-usv',
            '0xaef0d72a118ce24fee3cd1d43d383897d05b4e99': 'winklink-bsc',
            '0xacb2d47827c9813ae26de80965845d80935afd0b': 'macaronswap',
            '0xaf53d56ff99f1322515e54fdde93ff8b3b7dafd5': 'prometeus',
            '0xaec945e04baf28b135fa7c640f624f8d90f1c3a6': 'coin98',
            '0xace3574b8b054e074473a9bd002e5dc6dd3dff1b': 'rbx-token',
            '0xac472d0eed2b8a2f57a6e304ea7ebd8e88d1d36f': 'anime-token',
            '0xa9c41a46a6b3531d28d5c32f6633dd2ff05dfb90': 'waultswap',
            '0xa2b726b1145a4773f68593cf171187d8ebe4d495': 'injective-protocol',
            '0xa1faa113cbe53436df28ff0aee54275c13b40975': 'alpha-finance',
            '0xa184088a740c695e156f91f5cc086a06bb78b827': 'auto',
            '0xa045e37a0d1dd3a45fefb8803d22457abc0a728a': 'grizzly-honey',
            '0xffba7529ac181c2ee1844548e6d7061c9a597df4': 'coin-capsule',
            '0xfd7b3a77848f1c2d67e05e54d78d174a0c850335': 'binance-peg-ontology',
            '0xfa40d8fc324bcdd6bbae0e086de886c571c225d4': 'wizardia',
            '0xfa262f303aa244f9cc66f312f0755d89c3793192': 'rigel-protocol',
            '0xf952fc3ca7325cc27d15885d37117676d25bfda6': 'goose-finance',
            '0xf8a0bf9cf54bb92f17374d9e9a321e6a111a51bd': 'chainlink',
            '0xf7b6d7e3434cb9441982f9534e6998c43eef144a': 'asva',
            '0xf78d2e7936f5fe18308a3b2951a93b6c4a41f5e2': 'mantra-dao',
            '0xf7844cb890f4c339c497aeab599abdc3c874b67a': 'nft-art-finance',
            '0xf606bd19b1e61574ed625d9ea96c841d4e247a32': 'guardian-token',
            '0xf5d8a096cccb31b9d7bce5afe812be23e3d4690d': 'happyfans',
            '0xf4ed363144981d3a65f42e7d0dc54ff9eef559a1': 'faraland',
            '0xf218184af829cf2b0019f8e6f0b2423498a36983': 'math',
            '0xf21768ccbc73ea5b6fd3c687208a7c2def2d966e': 'reef',
            '0xf0dcf7ac48f8c745f2920d03dff83f879b80d438': 'gami',
            '0xee9801669c6138e84bd50deb500827b776777d28': 'o3-swap',
            '0xed8c8aa8299c10f067496bb66f8cc7fb338a3405': 'prosper',
            '0xeca41281c24451168a37211f0bc2b8645af45092': 'token-pocket',
            '0xe9c803f48dffe50180bd5b01dc04da939e3445fc': 'velas',
            '0xe8176d414560cfe1bf82fd73b986823b89e4f545': 'step-hero',
            '0xe5ba47fd94cb645ba4119222e34fb33f59c7cd90': 'safuu',
            '0xe4fae3faa8300810c835970b9187c268f55d998f': 'catecoin',
            '0xe336a772532650bc82828e9620dd0d5a3b78bfe8': 'digimetaverse',
            '0xe0e514c71282b6f4e823703a39374cf58dc3ea4f': 'belt',
            '0xe02df9e3e622debdd69fb838bb799e3f168902c5': 'bakerytoken',
            '0xddc0dbd7dc799ae53a98a60b54999cb6ebb3abf0': 'safeblast',
            '0xdb021b1b247fe2f1fa57e0a87c748cc1e321f07f': 'ampleforth',
            '0xdae6c2a48bfaa66b43815c5548b10800919c993e': 'kattana',
            '0xd9c2d319cd7e6177336b0a9c93c21cb48d84fb54': 'hapi',
            '0xd98560689c6e748dc37bc410b4d3096b1aa3d8c2': 'defi-for-you',
            '0xd8047afecb86e44eff3add991b9f063ed4ca716b': 'good-games-guild',
            '0xd7730681b1dc8f6f969166b29d8a5ea8568616a3': 'nafter',
            '0xd74b782e05aa25c50e7330af541d46e18f36661c': 'richquack',
            '0xd48474e7444727bf500a32d5abe01943f3a59a64': 'bitbook-token',
            '0xd44fd09d74cd13838f137b590497595d6b3feea4': 'cryptomines-eternal',
            '0xd41fdb03ba84762dd66a0af1a6c8540ff1ba5dfb': 'safepal',
            '0xd40bedb44c081d2935eeba6ef5a3c8a31a1bbe13': 'metahero',
            '0xd3c325848d7c6e29b574cb0789998b2ff901f17e': '1art',
            '0xc9849e6fdb743d08faee3e34dd2d1bc69ea11a51': 'pancake-bunny',
            '0xc5326b32e8baef125acd68f8bc646fd646104f1c': 'zap',
            '0xc3028fbc1742a16a5d69de1b334cbce28f5d7eb3': 'starsharks',
            '0xc13b7a43223bb9bf4b69bd68ab20ca1b79d81c75': 'juggernaut',
            '0xc1165227519ffd22fdc77ceb1037b9b284eef068': 'bnsd-finance',
            '0xc0eff7749b125444953ef89682201fb8c6a917cd': 'horizon-protocol',
            '0xc0ecb8499d8da2771abcbf4091db7f65158f1468': 'switcheo',
            '0xbf5140a22578168fd562dccf235e5d43a02ce9b1': 'uniswap',
            '0xbe1a001fe942f96eea22ba08783140b9dcc09d28': 'beta-finance',
            '0xbd2949f67dcdc549c6ebe98696449fa79d988a9f': 'meter',
            '0xbc7d6b50616989655afd682fb42743507003056d': 'alchemy-pay',
            '0xbb46693ebbea1ac2070e59b4d043b47e2e095f86': 'bfg-token',
            '0xbac1df744df160877cdc45e13d0394c06bc388ff': 'nftmall',
            '0xbf05279f9bf1ce69bbfed670813b7e431142afa4': 'million',
            '0xbc7370641ddcf16a27eea11230af4a9f247b61f9': 'xana',
            '0xbbca42c60b5290f2c48871a596492f93ff0ddc82': 'domi',
            '0xb5102cee1528ce2c760893034a4603663495fd72': 'token-dforce-usd',
            '0xb44c63a09adf51f5e62cc7b63628b1b789941fa0': 'reflex',
            '0xb2bd0749dbe21f623d9baba856d3b0f0e1bfec9c': 'dusk-network',
            '0xb248a295732e0225acd3337607cc01068e3b9c10': 'venus-xrp',
            '0xb149b030cfa47880af0bde4cd36539e4c928b3eb': 'nutgain',
            '0xb0e1fc65c1a741b4662b813eb787d369b8614af1': 'impossible-finance',
            '0xb0d502e938ed5f4df2e681fe6e419ff29631d62b': 'stargate-finance',
            '0xb0b195aefa3650a6908f15cdac7d92f8a5791b0b': 'bob',
            '0xae9269f27437f0fcbc232d39ec814844a51d6b8f': 'burger-swap',
            '0xae2df9f730c54400934c06a17462c41c08a06ed8': 'dogebonk',
            '0xad6742a35fb341a9cc6ad674738dd8da98b94fb1': 'wombat-exchange',
            '0xad29abb318791d579433d831ed122afeaf29dcfe': 'wrapped-fantom',
            '0xacb8f52dc63bb752a51186d1c55868adbffee9c1': 'bunnypark',
            '0xac51066d7bec65dc4589368da368b212745d63e8': 'my-neighbor-alice',
            '0xa58950f05fea2277d2608748412bf9f802ea4901': 'wall-street-games',
            '0xa57ac35ce91ee92caefaa8dc04140c8e232c2e50': 'pitbull',
            '0xa4b6573c9ae09d81e4d1360e6402b81f52557098': 'coreto',
            '0xa2120b9e674d3fc3875f415a7df52e382f141225': 'automata',
            '0x9fd87aefe02441b123c3c32466cd9db4c578618f': 'thetan-arena',
            '0x9f589e3eabe42ebc94a44727b3f3531c0c877809': 'tokocrypto',
            '0x9c67638c4fa06fd47fb8900fc7f932f7eab589de': 'arker-2',
            '0x9fb9a33956351cf4fa040f65a13b835a3c8764e3': 'multichain-bsc',
            '0x9d173e6c594f479b4d47001f8e6a95a7adda42bc': 'cryptozoon',
            '0x9c65ab58d8d978db963e63f2bfb7121627e3a739': 'mdex-bsc',
            '0x9ba6a67a6f3b21705a46b380a1b97373a33da311': 'fear',
            '0x9ab70e92319f0b9127df78868fd3655fb9f1e322': 'weway',
            '0x99c6e435ec259a7e8d65e1955c9423db624ba54c': 'finminity',
            '0x9678e42cebeb63f23197d726b29b1cb20d0064e5': 'binance-peg-iotex',
            '0x965b0df5bda0e7a0649324d78f03d5f7f2de086a': 'cook',
            '0x965f527d9159dce6288a2219db51fc6eef120dd1': 'biswap',
            '0x9617857e191354dbea0b714d78bc59e57c411087': 'lympo-market-token',
            '0x95c78222b3d6e262426483d42cfa53685a67ab9d': 'venus-busd',
            '0x95a1199eba84ac5f19546519e287d43d2f0e1b41': 'rabbit-finance',
            '0x95ee03e1e2c5c4877f9a298f1c0d6c98698fab7b': 'duet-protocol',
            '0x9573c88ae3e37508f87649f87c4dd5373c9f31e0': 'monsta-infinite',
            '0x9528cceb678b90daf02ca5ca45622d5cbaf58a30': 'gocryptome',
            '0x94b69263fca20119ae817b6f783fc0f13b02ad50': 'league-of-ancients',
            '0x949d48eca67b17269629c7194f4b727d4ef9e5d6': 'merit-circle',
            '0x948d2a81086a075b3130bac19e4c6dee1d2e3fe8': 'helmet-insure',
            '0x947950bcc74888a40ffa2593c5798f11fc9124c4': 'sushi',
            '0x936b6659ad0c1b244ba8efe639092acae30dc8d6': 'corite',
            '0x4c882ec256823ee773b25b414d36f92ef58a7c0c': 'pstake-finance',
            '0x4c769928971548eb71a3392eaf66bedc8bef4b80': 'harrypotterobamasonic10inu',
            '0x4bd17003473389a42daf6a0a729f6fdb328bbbd7': 'vai',
            '0x4ba0057f784858a48fe351445c672ff2a3d43515': 'kalmar',
            '0x489580eb70a50515296ef31e8179ff3e77e24965': 'dappradar',
            '0x482e6bd0a178f985818c5dfb9ac77918e8412fba': 'colizeum',
            '0x4803ac6b79f9582f69c4fa23c72cb76dd1e46d8d': 'topmanager',
            '0x47bead2563dcbf3bf2c9407fea4dc236faba485a': 'swipe',
            '0x477bc8d23c634c154061869478bce96be6045d12': 'seedify-fund',
            '0x475bfaa1848591ae0e6ab69600f48d828f61a80e': 'everdome',
            '0x474021845c4643113458ea4414bdb7fb74a01a77': 'uno-re',
            '0x46d502fac9aea7c5bc7b13c8ec9d02378c33d36f': 'wolfsafepoorpeople',
            '0x4691937a7508860f876c9c0a2a617e7d9e945d4b': 'woo-network',
            '0x44ec807ce2f4a6f2737a92e985f318d035883e47': 'hashflow',
            '0x44754455564474a89358b2c2265883df993b12f0': 'zeroswap',
            '0x43f5b29d63cedc5a7c1724dbb1d698fde05ada21': 'fodl-finance',
            '0x4374f26f0148a6331905edf4cd33b89d8eed78d1': 'yoshi-exchange',
            '0x4338665cbb7b2485a8855a139b75d5e34ab0db94': 'binance-peg-litecoin',
            '0x42f6f551ae042cbe50c739158b4f0cac0edb9096': 'nerve-finance',
            '0x426c72701833fddbdfc06c944737c6031645c708': 'defina-finance',
            '0x422e3af98bc1de5a1838be31a56f75db4ad43730': 'coinwind',
            '0x4197c6ef3879a08cd51e5560da5064b773aa1d29': 'acryptos',
            '0x410a56541bd912f9b60943fcb344f1e3d6f09567': 'minto',
            '0x41065e3428188ba6eb27fbdde8526ae3af8e3830': 'swash',
            '0x40c8225329bd3e28a043b029e0d07a5344d2c27c': 'ageofgods',
            '0x3c6dad0475d3a1696b359dc04c99fd401be134da': 'saito',
            '0x3b198e26e473b8fab2085b37978e36c9de5d7f68': 'chronobank',
            '0x3ad9594151886ce8538c1ff615efa2385a8c3a88': 'safemars',
            '0x3fcca8648651e5b974dd6d3e50f61567779772a8': 'moonpot',
            '0x3f56e0c36d275367b8c502090edf38289b3dea0d': 'mai-bsc',
            '0x3ee2200efb3400fabb9aacf31297cbdd1d435d47': 'binance-peg-cardano',
            '0x3da932456d082cba208feb0b096d49b202bf89c8': 'dego-finance',
            '0x3c45a24d36ab6fc1925533c1f57bc7e1b6fba8a4': 'option-room',
            '0x368ce786ea190f32439074e8d22e12ecb718b44c': 'epik-prime',
            '0x352cb5e19b12fc216548a2677bd0fce83bae434b': 'bittorrent',
            '0x347e430b7cd1235e216be58ffa13394e5009e6e2': 'gaia-everworld',
            '0x339c72829ab7dd45c3c52f965e7abe358dd8761e': 'wanaka-farm',
            '0x334b3ecb4dca3593bccc3c7ebd1a1c1d1780fbf1': 'venus-dai',
            '0x32f1518baace69e85b9e5ff844ebd617c52573ac': 'dexsport',
            '0x3203c9e46ca618c8c1ce5dc67e7e9d75f5da2377': 'mobox',
            '0x31d0a7ada4d4c131eb612db48861211f63e57610': 'bscstarter',
            '0x3192ccddf1cdce4ff055ebc80f3f0231b86a7e30': 'insurace',
            '0x31471e0791fcdbe82fbf4c44943255e923f1b794': 'plant-vs-undead-token',
            '0x30807d3b851a31d62415b8bb7af7dca59390434a': 'radioshack',
            '0x3019bf2a2ef8040c242c9a4c5c4bd4c81678b2a1': 'stepn',
            '0x2ff3d0f6990a40261c66e1ff2017acbc282eb6d0': 'venus-sxp',
            '0x2ff0b946a6782190c4fe5d4971cfe79f0b6e4df2': 'mysterium',
            '0x2ed9a5c8c13b93955103b9a7c167b67ef4d568a3': 'mask-network',
            '0x2fa5daf6fe0708fbd63b1a7d1592577284f52256': 'unmarshal',
            '0x2c717059b366714d267039af8f59125cadce6d8c': 'metashooter',
            '0x2ab0e9e4ee70fff1fb9d67031e44f6410170d00e': 'xen-crypto-bsc',
            '0x2a48ece377b87ce941406657b9278b4459595e06': 'lunatics',
            '0x29a63f4b209c29b4dc47f06ffa896f32667dad2c': 'pundi-x-purse',
            '0x2859e4544c4bb03966803b044a93563bd2d0dd4d': 'binance-peg-shib',
            '0x27ae27110350b98d564b9a3eed31baebc82d878d': 'cumrocket',
            '0x26d3163b165be95137cee97241e716b2791a7572': 'dibs-share',
            '0x250632378e573c6be1ac2f97fcdf00515d0aa91b': 'binance-eth',
            '0x23e8a70534308a4aaf76fb8c32ec13d17a3bd89e': 'lusd',
            '0x23b8683ff98f9e4781552dfe6f12aa32814924e8': 'jarvis-synthetic-euro',
            '0x23ce9e926048273ef83be0a3a8ba9cb6d45cd978': 'mines-of-dalarnia',
            '0x23396cf899ca06c4472205fc903bdb4de249d6fc': 'wrapped-ust',
            '0x232fb065d9d24c34708eedbf03724f2e95abe768': 'sheesha-finance',
            '0x20de22029ab63cf9a7cf5feb2b737ca1ee4c82a6': 'tranchess',
            '0x1d6cbdc6b29c6afbae65444a1f65ba9252b8ca83': 'tor',
            '0x1bdd3cf7f79cfb8edbb955f20ad99211551ba275': 'stader-bnbx',
            '0x1ba8d3c4c219b124d351f603060663bd1bcd9bbf': 'tornado-cash',
            '0x1a9b49e9f075c37fe5f86c916bac9deb33556d7e': 'aspo-world',
            '0x1fa4a73a3f0133f0025378af00236f3abdee5d63': 'binance-peg-near-protocol',
            '0x1ffd0b47127fdd4097e54521c9e2c7f0d66aafc5': 'autobahn-network',
            '0x1f39dd2bf5a27e2d4ed691dcf933077371777cb0': 'snowcrash-token',
            '0x1d3437e570e93581bd94b2fd8fbf202d4a65654a': 'nanobyte',
            '0x1d2f0da169ceb9fc7b3144628db156f3f6c60dbe': 'binance-peg-xrp',
            '0x1d229b958d5ddfca92146585a8711aecbe56f095': 'zoo-crypto-world',
            '0x1ce0c2827e2ef14d5c4f29a091d735a204794041': 'binance-peg-avalanche',
            '0x1bf7aedec439d6bfe38f8f9b20cf3dc99e3571c4': 'tronpad',
            '0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3': 'binance-peg-dai',
            '0x19e6bfc1a6e4b042fb20531244d47e252445df01': 'templardao',
            '0x19a4866a85c652eb4a2ed44c42e4cb2863a62d51': 'hodooi-com',
            '0x190b589cf9fb8ddeabbfeae36a813ffb2a702454': 'bdollar',
            '0x181de8c57c4f25eba9fd27757bbd11cc66a55d31': 'beluga-fi',
            '0x17b7163cf1dbd286e262ddc68b553d899b93f526': 'qubit',
            '0x1796ae0b0fa4862485106a0de9b654efe301d0b2': 'polychain-monsters',
            '0x1785113910847770290f5f840b4c74fc46451201': 'fabwelt',
            '0x16939ef78684453bfdfb47825f8a5f714f12623a': 'binance-peg-tezos-token',
            '0x1633b7157e7638c4d6593436111bf125ee74703f': 'splinterlands',
            '0x1613957159e9b0ac6c80e824f7eea748a32a0ae2': 'chain-guardians',
            '0x154a9f9cbd3449ad22fdae23044319d6ef2a1fab': 'cryptoblades',
            '0x151b1e2635a717bcdc836ecd6fbb62b674fe3e1d': 'venus-xvs',
            '0x14c358b573a4ce45364a3dbd84bbb4dae87af034': 'dungeonswap',
            '0x14a9a94e555fdd54c21d7f7e328e61d7ebece54b': 'loot',
            '0x14016e85a25aeb13065688cafb43044c2ef86784': 'bridged-trueusd',
            '0x0cbd6fadcf8096cc9a43d90b45f65826102e3ece': 'checkdot',
            '0x0b3f42481c228f70756dbfa0309d3ddc2a5e0f6a': 'ultrasafe',
            '0x0b15ddf19d47e6a86a56148fb4afffc6929bcb89': 'idia',
            '0x0a3a21356793b49154fd3bbe91cbc2a16c0457f5': 'redfox-labs-2',
            '0x0eb3a705fc54725037cc9e008bdede697f62f335': 'cosmos',
            '0x0e7beec376099429b85639eb3abe7cf22694ed49': 'bunicorn',
            '0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82': 'pancakeswap-token',
            '0x0d8ce2a99bb6e3b7db580ed848240e4a0f9ae153': 'binance-peg-filecoin',
            '0x09f423ac3c9babbff6f94d372b16e4206e71439f': 'enjinstarter',
            '0x08ba0619b1e7a582e0bce5bbe9843322c954c340': 'binamon',
            '0x0864c156b3c5f69824564dec60c629ae6401bf2a': 'streamr',
            '0x08037036451c768465369431da5c671ad9b37dbc': 'nft-stars',
            '0x0782b6d8c4551b9760e74c0545a9bcd90bdc41e5': 'helio-protocol-hay',
            '0x076ddce096c93dcf5d51fe346062bf0ba9523493': 'paralink-network',
            '0x0565805ca3a4105faee51983b0bd8ffb5ce1455c': 'blockchainspace',
            '0x04c747b40be4d535fc83d09939fb0f626f32800b': 'itam-games',
            '0x04baf95fd4c52fd09a56d840baee0ab8d7357bf0': 'one',
            '0x03ff0ff224f904be3118461335064bb48df47938': 'wrapped-one',
            '0x0391be54e72f7e001f6bbc331777710b4f2999ef': 'trava-finance',
            '0x037838b556d9c9d654148a284682c55bb5f56ef4': 'lightning-protocol',
            '0x02ff5065692783374947393723dba9599e59f591': 'yooshi',
            '0x02a40c048ee2607b5f5606e445cfc3633fb20b58': 'kaby-arena',
            '0x0288d3e353fe2299f11ea2c2e1696b4a648ecc07': 'zcore-finance',
            '0x0255af6c9f86f6b0543357bacefa262a2664f80f': 'immutable',
            '0x0231f91e02debd20345ae8ab7d71a41f8e140ce7': 'jupiter',
            '0x016cf83732f1468150d87dcc5bdf67730b3934d3': 'airnft-token',
            '0x00e1656e45f18ec6747f5a8496fd39b50b38396d': 'bomber-coin',
            '0x4437743ac02957068995c48e08465e0ee1769fbe': 'fortress',
            '0x47c454ca6be2f6def6f32b638c80f91c9c3c5949': 'games-for-a-living',
            '0x8263cd1601fe73c066bf49cc09841f35348e3be0': 'altura',
            '0x868fced65edbf0056c4163515dd840e9f287a4c3': 'sign-global',
            '0x14778860e937f509e651192a90589de711fb88a9': 'cyberconnect'
        }
    
    please = {k.lower(): v for k, v in please.items()}
    if contract_address.lower() in please:
        return please[contract_address.lower()]

    url = f"https://api.coingecko.com/api/v3/coins/{chain_map[chain]}/contract/{contract_address}"
    res = config.requests.get(url)
    if res.status_code != 200:
        print(f"CoinGecko ID lookup failed: {res.status_code}")
        return None
    return res.json().get('id')

def get_circulating_supply(coingecko_id):

    supplies = {
  "0xa49d7499271ae71cd8ab9ac515e6694c755d400c": {
    "id": "mute",
    "circulating_supply": 40000000.0
  },
  "0x26a604dffe3ddab3bee816097f81d3c4a2a4cf97": {
    "id": "corionx",
    "circulating_supply": 95442854.0
  },
  "0x8baf5d75cae25c7df6d1e0d26c52d19ee848301a": {
    "id": "catalorian",
    "circulating_supply": 1000000000.0
  },
  "0xec12ba5ac0f259e9ac6fc9a3bc23a76ad2fde5d9": {
    "id": "hugewin",
    "circulating_supply": 0.0
  },
  "0xfbd5fd3f85e9f4c5e8b40eec9f8b8ab1caaa146b": {
    "id": "treat-token",
    "circulating_supply": 0.0
  },
  "0xa2b8e02ce95b54362f8db7273015478dd725d7e7": {
    "id": "meme-cup",
    "circulating_supply": 1000000000.0
  },
  "0x4b7ffcb2b92fb4890f22f62a52fb7a180eab818e": {
    "id": "diva-protocol",
    "circulating_supply": 0.0
  },
  "0x76bc677d444f1e9d57daf5187ee2b7dc852745ae": {
    "id": "offshift",
    "circulating_supply": 10072791.006765
  },
  "0xa6c0c097741d55ecd9a3a7def3a8253fd022ceb9": {
    "id": "concierge-io",
    "circulating_supply": 69949531.0
  },
  "0x0b38210ea11411557c13457d4da7dc6ea731b88a": {
    "id": "api3",
    "circulating_supply": 129056136.8742702
  },
  "0x0aee8703d34dd9ae107386d3eff22ae75dd616d1": {
    "id": "tranche-finance",
    "circulating_supply": 17419343.11214679
  },
  "0x06ddb3a8bc0abc14f85e974cf1a93a6f8d4909d9": {
    "id": "8pay",
    "circulating_supply": 64727636.28359083
  },
  "0x73374ea518de7addd4c2b624c0e8b113955ee041": {
    "id": "juggernaut",
    "circulating_supply": 100210415.86298622
  },
  "0x17837004ea685690b32dbead02a274ec4333a26a": {
    "id": "bear-inu",
    "circulating_supply": 0.0
  },
  "0x75e88b8c2d34a52a6d36deada664d7dc9116e4ef": {
    "id": "zaros",
    "circulating_supply": 99470277.59264632
  },
  "0x60e254e35dd712394b3aba7a1d19114732e143dd": {
    "id": "rivusdao",
    "circulating_supply": 294667207.1227077
  },
  "0x7b66e84be78772a3afaf5ba8c1993a1b5d05f9c2": {
    "id": "vitarna",
    "circulating_supply": 2270744.7071931246
  },
  "0x9be89d2a4cd102d8fecc6bf9da793be995c22541": {
    "id": "binance-wrapped-btc",
    "circulating_supply": 0.0
  },
  "0x249ca82617ec3dfb2589c4c17ab7ec9765350a18": {
    "id": "verse-bitcoin",
    "circulating_supply": 41803786000.0
  },
  "0x285db79fa7e0e89e822786f48a7c98c6c1dc1c7d": {
    "id": "magic-internet-cash",
    "circulating_supply": 0.0
  },
  "0xa0084063ea01d5f09e56ef3ff6232a9e18b0bacd": {
    "id": "cyberdex",
    "circulating_supply": 315661611.09248054
  },
  "0xe973e453977195422b48e1852a207b7ee9c913c7": {
    "id": "adreward",
    "circulating_supply": 9333333344.0
  },
  "0xd8c978de79e12728e38aa952a6cb4166f891790f": {
    "id": "og-roaring-kitty",
    "circulating_supply": 1000000000.0
  },
  "0x68aae81b4241ffe03d3552d42a69940604fe28bf": {
    "id": "muffin",
    "circulating_supply": 0.0
  },
  "0x4e4990e997e1df3f6b39ff49384e2e7e99bc55fe": {
    "id": "saudi-bonk",
    "circulating_supply": 0.0
  },
  "0xc8d3dcb63c38607cb0c9d3f55e8ecce628a01c36": {
    "id": "matrixswap",
    "circulating_supply": 33920798.6666667
  },
  "0x6069c9223e8a5da1ec49ac5525d4bb757af72cd8": {
    "id": "musk-gold",
    "circulating_supply": 34521000.0
  },
  "0x48f9e38f3070ad8945dfeae3fa70987722e3d89c": {
    "id": "infinifi-usd",
    "circulating_supply": 116648264.1656249
  },
  "0x7afd0d633e0a2b1db97506d97cadc880c894eca9": {
    "id": "marutaro-2",
    "circulating_supply": 9057384878.913288
  },
  "0xaddb6dc7e2f7caea67621dd3ca2e8321ade33286": {
    "id": "sharp-ai",
    "circulating_supply": 0.0
  },
  "0xf293d23bf2cdc05411ca0eddd588eb1977e8dcd4": {
    "id": "sylo",
    "circulating_supply": 6419652099.391
  },
  "0xd5930c307d7395ff807f2921f12c5eb82131a789": {
    "id": "bolt",
    "circulating_supply": 998999999.9999999
  },
  "0x4ae149fd6059af772b962efac6bf0236872d6940": {
    "id": "lemmy-the-bat",
    "circulating_supply": 69000000000.0
  },
  "0xcab84bc21f9092167fcfe0ea60f5ce053ab39a1e": {
    "id": "block-4",
    "circulating_supply": 470000000.0
  },
  "0x82d36570842fc1ac2a3b4dbe0e7c5c0e2e665090": {
    "id": "nfinityai",
    "circulating_supply": 0.0
  },
  "0xf57e7e7c23978c3caec3c3548e3d615c346e79ff": {
    "id": "immutable-x",
    "circulating_supply": 1939938090.3898141
  },
  "0xd2adc1c84443ad06f0017adca346bd9b6fc52cab": {
    "id": "dfund",
    "circulating_supply": 332447042.9283598
  },
  "0x54991328ab43c7d5d31c19d1b9fa048e77b5cd16": {
    "id": "soil",
    "circulating_supply": 42168801.08716577
  },
  "0x35bd01fc9d6d5d81ca9e055db88dc49aa2c699a8": {
    "id": "friends-with-benefits-pro",
    "circulating_supply": 597463.7112890496
  },
  "0xff8c479134a18918059493243943150776cf8cf2": {
    "id": "renq-finance",
    "circulating_supply": 0.0
  },
  "0x381491960c37b65862819ced0e35385f04b2c78b": {
    "id": "hachiko-2",
    "circulating_supply": 0.0
  },
  "0x89e8e084cc60e6988527f0904b4be71656e8bfa9": {
    "id": "smog",
    "circulating_supply": 0.0
  },
  "0x2d5d69da90b4c02b95c802344b48e3e57ce220d7": {
    "id": "beware-of-geeks-bearing-grifts",
    "circulating_supply": 1000000000000.0
  },
  "0x3541a5c1b04adaba0b83f161747815cd7b1516bc": {
    "id": "citadao",
    "circulating_supply": 1455205480.46094
  },
  "0x9393fdc77090f31c7db989390d43f454b1a6e7f3": {
    "id": "dark-energy-crystals",
    "circulating_supply": 0.0
  },
  "0xd073e6341a3aa6c4d94c4f8f20fbd1ede572b0da": {
    "id": "metacene",
    "circulating_supply": 533950616.4810331
  },
  "0x270b7748cdf8243bfe68face7230ef0fce695389": {
    "id": "hinkal-staked-eth",
    "circulating_supply": 0.0
  },
  "0xbb8ecf8d1342e086c9a751ee1b31a8320007379f": {
    "id": "nexara",
    "circulating_supply": 1000000000.0
  },
  "0x2f573070e6090b3264fe707e2c9f201716f123c7": {
    "id": "mumu",
    "circulating_supply": 688486242717629.5
  },
  "0x5bb29c33c4a3c29f56f8aca40b4db91d8a5fe2c5": {
    "id": "one-share",
    "circulating_supply": 0.0
  },
  "0xff931a7946d2fa11cf9123ef0dc6f6c7c6cb60c4": {
    "id": "dancing-baby",
    "circulating_supply": 0.0
  },
  "0x44108f0223a3c3028f5fe7aec7f9bb2e66bef82f": {
    "id": "across-protocol",
    "circulating_supply": 610025005.0358385
  },
  "0x3301ee63fb29f863f2333bd4466acb46cd8323e6": {
    "id": "akita-inu",
    "circulating_supply": 0.0
  },
  "0x0808e6c4400bde1d70db0d02170b67de05e07ef5": {
    "id": "wrapped-lyx-sigmaswap",
    "circulating_supply": 0.0
  },
  "0xac6708e83698d34cd5c09d48249b0239008d0ccf": {
    "id": "fort-knox",
    "circulating_supply": 1000000000.0
  },
  "0xe842e272a18625319cc36f64eb9f97e5ad0c32af": {
    "id": "yak",
    "circulating_supply": 0.0
  },
  "0x004f747a91e05d0e2fbe8bf3cd39cdb2bcfab02c": {
    "id": "tweet",
    "circulating_supply": 0.0
  },
  "0x28e67eb7aaa8f5dd9cb7be2b2e3dad6b25edb1ab": {
    "id": "freaky-keke",
    "circulating_supply": 0.0
  },
  "0x80f0c1c49891dcfdd40b6e0f960f84e6042bcb6f": {
    "id": "dbxen",
    "circulating_supply": 0.0
  },
  "0x8fe815417913a93ea99049fc0718ee1647a2a07c": {
    "id": "xswap-2",
    "circulating_supply": 273072768.1818102
  },
  "0x4947b72fed037ade3365da050a9be5c063e605a7": {
    "id": "peanut-2",
    "circulating_supply": 420690000000.0
  },
  "0x39795344cbcc76cc3fb94b9d1b15c23c2070c66d": {
    "id": "seigniorage-shares",
    "circulating_supply": 19403624.67
  },
  "0x926759a8eaecfadb5d8bdc7a9c7b193c5085f507": {
    "id": "nura-labs",
    "circulating_supply": 8906900000.0
  },
  "0x8561d6829189db74ea1165b7d2bc633616891695": {
    "id": "flo",
    "circulating_supply": 9000000.0
  },
  "0x7434a5066dc317fa5b4d31aaded5088b9c54d667": {
    "id": "cult",
    "circulating_supply": 0.0
  },
  "0x8c543aed163909142695f2d2acd0d55791a9edb9": {
    "id": "velas",
    "circulating_supply": 2751422972.094905
  },
  "0xcda4e840411c00a614ad9205caec807c7458a0e3": {
    "id": "purefi",
    "circulating_supply": 93466552.8636034
  },
  "0x955d5c14c8d4944da1ea7836bd44d54a8ec35ba1": {
    "id": "refund",
    "circulating_supply": 1000000000000.0
  },
  "0x8074836637eb9cc73a01a65d5700907fc639c4e9": {
    "id": "duelnow",
    "circulating_supply": 91798827.275385
  },
  "0x940a2db1b7008b6c776d4faaca729d6d4a4aa551": {
    "id": "dusk-network",
    "circulating_supply": 500000000.0
  },
  "0x14cf922aa1512adfc34409b63e18d391e4a86a2f": {
    "id": "eth-strategy",
    "circulating_supply": 30514888.08149964
  },
  "0xdbdb4d16eda451d0503b854cf79d55697f90c8df": {
    "id": "alchemix",
    "circulating_supply": 2479006.6899192664
  },
  "0x2620638eda99f9e7e902ea24a285456ee9438861": {
    "id": "crust-storage-market",
    "circulating_supply": 0.0
  },
  "0x8ab2ff0116a279a99950c66a12298962d152b83c": {
    "id": "ordiswap-token",
    "circulating_supply": 708700006.4464747
  },
  "0x147faf8de9d8d8daae129b187f0d02d819126750": {
    "id": "geodb",
    "circulating_supply": 177404745.88824433
  },
  "0xf75302720787c2a2176c87b1919059c4eaac8b98": {
    "id": "cfgi",
    "circulating_supply": 8186781686.0
  },
  "0x38d64ce1bdf1a9f24e0ec469c9cade61236fb4a0": {
    "id": "vector-eth",
    "circulating_supply": 29.53610023555432
  },
  "0x1634e10c9155be623b5a52d6ca01c7a904d89b0a": {
    "id": "this-is-fine-ethereum",
    "circulating_supply": 69000000000000.0
  },
  "0x6adb2e268de2aa1abf6578e4a8119b960e02928f": {
    "id": "shibadoge",
    "circulating_supply": 1.1570865912075508e+23
  },
  "0x25931894a86d47441213199621f1f2994e1c39aa": {
    "id": "chaingpt",
    "circulating_supply": 857188667.0
  },
  "0x677ddbd918637e5f2c79e164d402454de7da8619": {
    "id": "vesper-vdollar",
    "circulating_supply": 1975392.962539819
  },
  "0x9e3b5582b22e3835896368017baff6d942a41cd9": {
    "id": "haven1",
    "circulating_supply": 172321698.8948483
  },
  "0xa1f410f13b6007fca76833ee7eb58478d47bc5ef": {
    "id": "rejuve-ai",
    "circulating_supply": 535825511.524955
  },
  "0xba25b2281214300e4e649fead9a6d6acd25f1c0a": {
    "id": "tree-capital",
    "circulating_supply": 101361867.09737062
  },
  "0xf1f955016ecbcd7321c7266bccfb96c68ea5e49b": {
    "id": "rally-2",
    "circulating_supply": 5011892646.271167
  },
  "0x62959c699a52ec647622c91e79ce73344e4099f5": {
    "id": "define",
    "circulating_supply": 0.0
  },
  "0x33f391f4c4fe802b70b77ae37670037a92114a7c": {
    "id": "burp",
    "circulating_supply": 0.0
  },
  "0x830a8512db4f6fca51968593e2667156c2c483a8": {
    "id": "wen-token",
    "circulating_supply": 0.0
  },
  "0xc08512927d12348f6620a698105e1baac6ecd911": {
    "id": "gyen",
    "circulating_supply": 1085781048.057572
  },
  "0xfc10cd3895f2c66d6639ec33ae6360d6cfca7d6d": {
    "id": "yes-3",
    "circulating_supply": 75560.51028036515
  },
  "0xfbe44cae91d7df8382208fcdc1fe80e40fbc7e9a": {
    "id": "the-next-gem-ai",
    "circulating_supply": 0.0
  },
  "0x1258d60b224c0c5cd888d37bbf31aa5fcfb7e870": {
    "id": "nodeai",
    "circulating_supply": 97153156.22085401
  },
  "0x9b0b23b35ad8136e6181f22b346134ce5f426090": {
    "id": "cinogames",
    "circulating_supply": 0.0
  },
  "0x71ab77b7dbb4fa7e017bc15090b2163221420282": {
    "id": "highstreet",
    "circulating_supply": 0.0
  },
  "0xdc5e9445169c73cf21e1da0b270e8433cac69959": {
    "id": "ketaicoin",
    "circulating_supply": 0.0
  },
  "0x255494b830bd4fe7220b3ec4842cba75600b6c80": {
    "id": "beast-seller",
    "circulating_supply": 69420000.0
  },
  "0x678e840c640f619e17848045d23072844224dd37": {
    "id": "cratos",
    "circulating_supply": 63515856592.0
  },
  "0xb74f399aac8335e44a50ffb8f7ece74b9db8c30e": {
    "id": "nala",
    "circulating_supply": 1000000000000000.0
  },
  "0xd555498a524612c67f286df0e0a9a64a73a7cdc7": {
    "id": "defrogs",
    "circulating_supply": 10000.0
  },
  "0x419905009e4656fdc02418c7df35b1e61ed5f726": {
    "id": "resupply",
    "circulating_supply": 9494927.99
  },
  "0x384efd1e8b05c23dc392a40cb4e515e2229a5243": {
    "id": "healix-ai",
    "circulating_supply": 10000000.0
  },
  "0xe34ba9cbdf45c9d5dcc80e96424337365b6fe889": {
    "id": "medusa-3",
    "circulating_supply": 200000000.0
  },
  "0xb244b3574a5627849fca2057e3854340def63071": {
    "id": "veil-exchange",
    "circulating_supply": 0.0
  },
  "0xc092a137df3cf2b9e5971ba1874d26487c12626d": {
    "id": "ring-ai",
    "circulating_supply": 100000000.0
  },
  "0xb58e61c3098d85632df34eecfb899a1ed80921cb": {
    "id": "frankencoin",
    "circulating_supply": 12377626.31679173
  },
  "0x5e362eb2c0706bd1d134689ec75176018385430b": {
    "id": "decentralized-validator-token",
    "circulating_supply": 0.0
  },
  "0x00000000051b48047be6dc0ada6de5c3de86a588": {
    "id": "baby-shiba-inu-erc",
    "circulating_supply": 394944472.5251239
  },
  "0xc00e94cb662c3520282e6f5717214004a7f26888": {
    "id": "compound-governance-token",
    "circulating_supply": 9457176.80919084
  },
  "0x3cb48aeb3d1abadc23d2d8a6894b3a68338381c2": {
    "id": "paladinai",
    "circulating_supply": 0.0
  },
  "0x0138f5e99cfdffbacf36e543800c19ef16fa294b": {
    "id": "prophet-3",
    "circulating_supply": 0.0
  },
  "0x8143182a775c54578c8b7b3ef77982498866945d": {
    "id": "wrapped-quil",
    "circulating_supply": 902285400.373132
  },
  "0x993864e43caa7f7f12953ad6feb1d1ca635b875f": {
    "id": "singularitydao",
    "circulating_supply": 90501179.2436193
  },
  "0xfa5047c9c78b8877af97bdcb85db743fd7313d4a": {
    "id": "rook",
    "circulating_supply": 761211.268917467
  },
  "0x6f2dec5da475333b0af4a3ffc9a33b0211a9a452": {
    "id": "cryptotwitter",
    "circulating_supply": 0.0
  },
  "0xe0ad1806fd3e7edf6ff52fdb822432e847411033": {
    "id": "onx-finance",
    "circulating_supply": 9883242.322942737
  },
  "0x5bdc32663ec75e85ff4abc2cae7ae8b606a2cfca": {
    "id": "cookies-protocol",
    "circulating_supply": 0.0
  },
  "0x5582a479f0c403e207d2578963ccef5d03ba636f": {
    "id": "salad",
    "circulating_supply": 123138617.72910252
  },
  "0x53be7be0ce7f92bcbd2138305735160fb799be4f": {
    "id": "neutaro",
    "circulating_supply": 147225076.0
  },
  "0x1cf4592ebffd730c7dc92c1bdffdfc3b9efcf29a": {
    "id": "waves",
    "circulating_supply": 100000000.0
  },
  "0x09395a2a58db45db0da254c7eaa5ac469d8bdc85": {
    "id": "subquery-network",
    "circulating_supply": 2875917167.468919
  },
  "0x814a870726edb7dfc4798300ae1ce3e5da0ac467": {
    "id": "dacat",
    "circulating_supply": 403085615079440.9
  },
  "0x3c8d2fce49906e11e71cb16fa0ffeb2b16c29638": {
    "id": "nifty-league",
    "circulating_supply": 1000000000.0
  },
  "0x05fe069626543842439ef90d9fa1633640c50cf1": {
    "id": "eve-ai",
    "circulating_supply": 86589838.49362345
  },
  "0xe1ec350ea16d1ddaff57f31387b2d9708eb7ce28": {
    "id": "pepechain",
    "circulating_supply": 0.0
  },
  "0x5f18ea482ad5cc6bc65803817c99f477043dce85": {
    "id": "agility",
    "circulating_supply": 0.0
  },
  "0xef8e456967122db4c3c160314bde8d2602ad6199": {
    "id": "wagmi-coin",
    "circulating_supply": 0.0
  },
  "0x91af0fbb28aba7e31403cb457106ce79397fd4e6": {
    "id": "aergo",
    "circulating_supply": 472499995.7689212
  },
  "0x9ab778f84b2397c7015f7e83d12eee47d4c26694": {
    "id": "bitecoin-2",
    "circulating_supply": 420690000.0
  },
  "0xfa704148d516b209d52c2d75f239274c8f8eaf1a": {
    "id": "octaspace",
    "circulating_supply": 40344916.4568056
  },
  "0x06561dc5cedcc012a4ea68609b17d41499622e4c": {
    "id": "noob",
    "circulating_supply": 0.0
  },
  "0x64b78325d7495d6d4be92f234fa3f3b8d8964b8b": {
    "id": "shopping-io-token",
    "circulating_supply": 99612728.0
  },
  "0x2c0687215aca7f5e2792d956e170325e92a02aca": {
    "id": "earth-2-essence",
    "circulating_supply": 0.0
  },
  "0x1559fa1b8f28238fd5d76d9f434ad86fd20d1559": {
    "id": "eden",
    "circulating_supply": 159148015.6260222
  },
  "0xf5f52266a57e6d7312da39bd7ab9527b9e975c40": {
    "id": "agent-virtual-machine",
    "circulating_supply": 53150000.0
  },
  "0x8ccd897ca6160ed76755383b201c1948394328c7": {
    "id": "balance-ai",
    "circulating_supply": 0.0
  },
  "0xc36983d3d9d379ddfb306dfb919099cb6730e355": {
    "id": "colle-ai",
    "circulating_supply": 0.0
  },
  "0x81987681443c156f881b70875724cc78b08ada26": {
    "id": "mirai-the-whiterabbit",
    "circulating_supply": 420690000000.0
  },
  "0xd16fd95d949f996e3808eeea0e3881c59e76ef1e": {
    "id": "paratoken-2",
    "circulating_supply": 36192262408.50999
  },
  "0x27f103f86070cc639fef262787a16887d22d8415": {
    "id": "fofo-token",
    "circulating_supply": 0.0
  },
  "0xfbb4f63821e706daf801e440a5893be59094f5cc": {
    "id": "faith-2",
    "circulating_supply": 0.0
  },
  "0x9ba77c059b5a59a220aa648a6bd97986fb1bf0a9": {
    "id": "agentsys-ai",
    "circulating_supply": 100000000.0
  },
  "0x103c45ffcf40f481a318480718501527929a89c3": {
    "id": "fragma",
    "circulating_supply": 100000000.0
  },
  "0x2c7f442aab99d5e18cfae2291c507c0b5f3c1eb5": {
    "id": "keko",
    "circulating_supply": 0.0
  },
  "0x0a9e3dde12e4519c9d89df69bd738490c9466bf4": {
    "id": "market-dominance",
    "circulating_supply": 550400094.910206
  },
  "0xc9fe6e1c76210be83dc1b5b20ec7fd010b0b1d15": {
    "id": "fringe-finance",
    "circulating_supply": 1000000000.0
  },
  "0xaf4144cd943ed5362fed2bae6573184659cbe6ff": {
    "id": "lizcoin",
    "circulating_supply": 0.0
  },
  "0x5362ca75aa3c0e714bc628296640c43dc5cb9ed6": {
    "id": "dejitaru-hoshi",
    "circulating_supply": 1000000000.0
  },
  "0x3ffeea07a27fab7ad1df5297fa75e77a43cb5790": {
    "id": "peipeicoin-vip",
    "circulating_supply": 420689619843583.06
  },
  "0x4e9fcd48af4738e3bf1382009dc1e93ebfce698f": {
    "id": "tao-inu",
    "circulating_supply": 926672684.8454887
  },
  "0x0fc2a55d5bd13033f1ee0cdd11f60f7efe66f467": {
    "id": "lagrange",
    "circulating_supply": 193000000.0
  },
  "0x397deb686c72384fad502a81f4d7fdb89e1f1280": {
    "id": "xels",
    "circulating_supply": 19588304.60982812
  },
  "0xf02c2dc9b3cb7f1ba21ccd82dff4ebc92da8996f": {
    "id": "tensorscan-ai",
    "circulating_supply": 0.0
  },
  "0x217ddead61a42369a266f1fb754eb5d3ebadc88a": {
    "id": "don-key",
    "circulating_supply": 66294797.279515356
  },
  "0xfb130d93e49dca13264344966a611dc79a456bc5": {
    "id": "dogegf",
    "circulating_supply": 2.754047939064418e+16
  },
  "0x5de869e3e62b0fb2c15573246ba3bb3fd97a2275": {
    "id": "sheboshis-2",
    "circulating_supply": 0.0
  },
  "0xb5130f4767ab0acc579f25a76e8f9e977cb3f948": {
    "id": "godcoin-2",
    "circulating_supply": 89900006.0
  },
  "0x96665680f4889891f3209713cb9a8205dce7278d": {
    "id": "nyx-cipher",
    "circulating_supply": 0.0
  },
  "0x799ebfabe77a6e34311eeee9825190b9ece32824": {
    "id": "braintrust",
    "circulating_supply": 0.0
  },
  "0xed4e879087ebd0e8a77d66870012b5e0dffd0fa4": {
    "id": "astropepex",
    "circulating_supply": 65000000000.0
  },
  "0xf59c6767dfb5aa9e908cb8d1831d02e53312e8ff": {
    "id": "eyzoai",
    "circulating_supply": 100000000.0
  },
  "0xb1c064c3f2908f741c9dea4afc5773238b53e6cc": {
    "id": "warioxrpdumbledoreyugioh69inu",
    "circulating_supply": 0.0
  },
  "0xebb66a88cedd12bfe3a289df6dfee377f2963f12": {
    "id": "oscar",
    "circulating_supply": 893521454.404922
  },
  "0x52662717e448be36cb54588499d5a8328bd95292": {
    "id": "tenshi",
    "circulating_supply": 0.0
  },
  "0x8c9532a60e0e7c6bbd2b2c1303f63ace1c3e9811": {
    "id": "renzo-restaked-lst",
    "circulating_supply": 25153.88123962677
  },
  "0x83e9f223e1edb3486f876ee888d76bfba26c475a": {
    "id": "blockchainspace",
    "circulating_supply": 455492813.49321496
  },
  "0xcb76314c2540199f4b844d4ebbc7998c604880ca": {
    "id": "strawberry-ai",
    "circulating_supply": 100000000.0
  },
  "0x1a11ea9d61588d756d9f1014c3cf0d226aedd279": {
    "id": "milei-token",
    "circulating_supply": 0.0
  },
  "0x666acd390fa42d5bf86e9c42dc2fa6f6b4b2d8ab": {
    "id": "gorth",
    "circulating_supply": 420690000000000.0
  },
  "0x473037de59cf9484632f4a27b509cfe8d4a31404": {
    "id": "green-satoshi-token-on-eth",
    "circulating_supply": 84333163.69
  },
  "0x473f4068073cd5b2ab0e4cc8e146f9edc6fb52cc": {
    "id": "nutcoin-meme",
    "circulating_supply": 21000000000000.0
  },
  "0x2015bc0be96be4aea2aabc95522109acfec84c30": {
    "id": "weth-hedz",
    "circulating_supply": 1000000000.0
  },
  "0x6df0e641fc9847c0c6fde39be6253045440c14d3": {
    "id": "dinero-2",
    "circulating_supply": 805539182.2300137
  },
  "0xd8dd38ca016f3e0b3bc545d33cce72af274ce075": {
    "id": "swing-xyz",
    "circulating_supply": 0.0
  },
  "0x910812c44ed2a3b611e4b051d9d83a88d652e2dd": {
    "id": "pledge-2",
    "circulating_supply": 1000000000.0
  },
  "0x782f97c02c6ace8a3677c4a4c495d048ad67dba2": {
    "id": "social-lens-ai",
    "circulating_supply": 100000000.0
  },
  "0xc4c75f2a0cb1a9acc33929512dc9733ea1fd6fde": {
    "id": "martin-shkreli-inu",
    "circulating_supply": 0.0
  },
  "0x584bc13c7d411c00c01a62e8019472de68768430": {
    "id": "hegic",
    "circulating_supply": 1077684725.0
  },
  "0x0000000000c5dc95539589fbd24be07c6c14eca4": {
    "id": "milady-cult-coin",
    "circulating_supply": 45832276898.207375
  },
  "0x28e58ee9932697f610de907a279684d30c407ba9": {
    "id": "depinet",
    "circulating_supply": 90035000.0
  },
  "0x9acb099a6460dead936fe7e591d2c875ae4d84b8": {
    "id": "tokabu",
    "circulating_supply": 4.2e+17
  },
  "0x270ca21eb1a37cfe0e9a0e7582d8f897e013cdff": {
    "id": "dogius-maximus",
    "circulating_supply": 1000000000.0
  },
  "0x19af07b52e5faa0c2b1e11721c52aa23172fe2f5": {
    "id": "memes-street",
    "circulating_supply": 0.0
  },
  "0xb01dd87b29d187f3e3a4bf6cdaebfb97f3d9ab98": {
    "id": "liquity-bold",
    "circulating_supply": 771153.2860687806
  },
  "0xea36af87df952fd4c9a05cd792d370909bbda8db": {
    "id": "official-k-pop",
    "circulating_supply": 7200000000.16
  },
  "0x65278f702019078e9ab196c0da0a6ee55e7248b7": {
    "id": "wrapped-dione",
    "circulating_supply": 866671305.4422795
  },
  "0xf418588522d5dd018b425e472991e52ebbeeeeee": {
    "id": "ethereum-push-notification-service",
    "circulating_supply": 90236482.0
  },
  "0x87de305311d5788e8da38d19bb427645b09cb4e5": {
    "id": "verox",
    "circulating_supply": 22638.59507217683
  },
  "0xb6ff96b8a8d214544ca0dbc9b33f7ad6503efd32": {
    "id": "sync-network",
    "circulating_supply": 161834143.28547114
  },
  "0x8f081eb884fd47b79536d28e2dd9d4886773f783": {
    "id": "bepay",
    "circulating_supply": 13000000.0
  },
  "0xf411903cbc70a74d22900a5de66a2dda66507255": {
    "id": "verasity",
    "circulating_supply": 85579723524.36942
  },
  "0x7bc3485026ac48b6cf9baf0a377477fff5703af8": {
    "id": "wrapped-aave-ethereum-usdt",
    "circulating_supply": 92730302.894191
  },
  "0x75d86078625d1e2f612de2627d34c7bc411c18b8": {
    "id": "agii",
    "circulating_supply": 0.0
  },
  "0x46fdcddfad7c72a621e8298d231033cc00e067c6": {
    "id": "department-of-government-efficiency-3",
    "circulating_supply": 100000000000.0
  },
  "0xd8695414822e25ab796c1d360914ddf510a01138": {
    "id": "kreaitor",
    "circulating_supply": 0.0
  },
  "0xaf8b894229bc800658ab0faf744e97c8c74c4321": {
    "id": "black-lemon-ai",
    "circulating_supply": 6414418.218045709
  },
  "0x817162975186d4d53dbf5a7377dd45376e2d2fc5": {
    "id": "reactive-network",
    "circulating_supply": 310000000.0
  },
  "0x4550003152f12014558e5ce025707e4dd841100f": {
    "id": "kaizen",
    "circulating_supply": 0.0
  },
  "0xaee433adebe0fbb88daa47ef0c1a513caa52ef02": {
    "id": "pontoon",
    "circulating_supply": 23508211.7865297
  },
  "0x73d7c860998ca3c01ce8c808f5577d94d545d1b4": {
    "id": "ix-swap",
    "circulating_supply": 180000000.0
  },
  "0x8236a87084f8b84306f72007f36f2618a5634494": {
    "id": "lombard-staked-btc",
    "circulating_supply": 13894.54959332002
  },
  "0x7849241ccff81511f26c2a86ef9d96624e948975": {
    "id": "acore-ai-token",
    "circulating_supply": 100000000.0
  },
  "0xe9732d4b1e7d3789004ff029f032ba3034db059c": {
    "id": "patriot",
    "circulating_supply": 10000000000.0
  },
  "0xd86571bfb6753c252764c4ae37fd54888774d32e": {
    "id": "kabosu-erc20",
    "circulating_supply": 1000000000.0
  },
  "0x38e68a37e401f7271568cecaac63c6b1e19130b4": {
    "id": "banana-gun",
    "circulating_supply": 4016562.657889563
  },
  "0xca76bf98b6e44df7360da8650e701f6d9d94bb58": {
    "id": "memelinked",
    "circulating_supply": 49550325.393270165
  },
  "0x24da31e7bb182cb2cabfef1d88db19c2ae1f5572": {
    "id": "shikoku",
    "circulating_supply": 945922760616895.8
  },
  "0x80122c6a83c8202ea365233363d3f4837d13e888": {
    "id": "messier",
    "circulating_supply": 884836293943.9
  },
  "0xd9ebbc7970e26b4eced7323b9331763e8272d011": {
    "id": "benji-bananas",
    "circulating_supply": 1642974778.020004
  },
  "0x3be7bf1a5f23bd8336787d0289b70602f1940875": {
    "id": "vidt-dao",
    "circulating_supply": 879770288.0
  },
  "0xcb43c88c980ff3a2c3f45f125d9886e7aabcd017": {
    "id": "freakoff",
    "circulating_supply": 1000000000.0
  },
  "0x256d1fce1b1221e8398f65f9b36033ce50b2d497": {
    "id": "alvey-chain",
    "circulating_supply": 116771480.36313438
  },
  "0x6006fc2a849fedaba8330ce36f5133de01f96189": {
    "id": "spaceswap-shake",
    "circulating_supply": 759.0
  },
  "0x52c7aa73dc430dab948eee73ea253383fd223420": {
    "id": "big-back-bitcoin",
    "circulating_supply": 8346564492.873661
  },
  "0x50327c6c5a14dcade707abad2e27eb517df87ab5": {
    "id": "wrapped-tron",
    "circulating_supply": 0.0
  },
  "0x75231f58b43240c9718dd58b4967c5114342a86c": {
    "id": "okb",
    "circulating_supply": 21000000.0
  },
  "0xcbfef8fdd706cde6f208460f2bf39aa9c785f05d": {
    "id": "kine-protocol",
    "circulating_supply": 20211925.03950293
  },
  "0x2559813bbb508c4c79e9ccce4703bcb1f149edd7": {
    "id": "hourglass",
    "circulating_supply": 97751977.44609132
  },
  "0x2047ab3072b52561596ce5e0131bdbb7c848538d": {
    "id": "bored",
    "circulating_supply": 0.0
  },
  "0x3256cade5f8cb1256ac2bd1e2d854dec6d667bdf": {
    "id": "mogutou",
    "circulating_supply": 0.0
  },
  "0x478156deabfac918369044d52a6bdb5cc5597994": {
    "id": "schrodinger-2",
    "circulating_supply": 0.0
  },
  "0xb2617246d0c6c0087f18703d576831899ca94f01": {
    "id": "zignaly",
    "circulating_supply": 1408940795.2396517
  },
  "0xb0415d55f2c87b7f99285848bd341c367feac1ea": {
    "id": "r0ar-token",
    "circulating_supply": 0.0
  },
  "0xf38deb975d9a34bc2b8f678de0c1d53692363851": {
    "id": "metabrawl",
    "circulating_supply": 0.0
  },
  "0xe7f58a92476056627f9fdb92286778abd83b285f": {
    "id": "decentraweb",
    "circulating_supply": 50372590.580256864
  },
  "0x3595e426a7808e2482667ee4e453ef280fbb9cf4": {
    "id": "nose-candy",
    "circulating_supply": 5997392076.024408
  },
  "0xe75f2acafba1ad56c5ed712ffbc1d31910e74396": {
    "id": "komputai",
    "circulating_supply": 0.0
  },
  "0x5fc111f3fa4c6b32eaf65659cfebdeed57234069": {
    "id": "0xgasless-2",
    "circulating_supply": 11000000.0
  },
  "0x740a5ac14d0096c81d331adc1611cf2fd28ae317": {
    "id": "plebz",
    "circulating_supply": 0.0
  },
  "0xaf05ce8a2cef336006e933c02fc89887f5b3c726": {
    "id": "lockheed-martin-inu",
    "circulating_supply": 0.0
  },
  "0x5e29cf3e3fed4df50acab95f8268e9ee26ea36f2": {
    "id": "dacxi",
    "circulating_supply": 10000000000.0
  },
  "0x0a907b0bbff60702b29a36b19718d99253cfbd9f": {
    "id": "qlix",
    "circulating_supply": 1000000.0
  },
  "0x716bb5e0839451068885250442a5b8377f582933": {
    "id": "fofar0x71",
    "circulating_supply": 0.0
  },
  "0x13e4b8cffe704d3de6f19e52b201d92c21ec18bd": {
    "id": "parallelai",
    "circulating_supply": 100000000.0
  },
  "0xfb19075d77a0f111796fb259819830f4780f1429": {
    "id": "fenerbahce-token",
    "circulating_supply": 0.0
  },
  "0xa1aa371e450c5aee7fff259cbf5cca9384227272": {
    "id": "pentagon-chain",
    "circulating_supply": 199773.11864046863
  },
  "0xf2a22b900dde3ba18ec2aef67d4c8c1a0dab6aac": {
    "id": "monkeys",
    "circulating_supply": 0.0
  },
  "0x70e36f6bf80a52b3b46b3af8e106cc0ed743e8e4": {
    "id": "ccomp",
    "circulating_supply": 0.0
  },
  "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0": {
    "id": "wrapped-steth",
    "circulating_supply": 3130604.035240258
  },
  "0x690031313d70c2545357f4487c6a3f134c434507": {
    "id": "qqq6900",
    "circulating_supply": 1000000000.0
  },
  "0x69420cb71f5fa439a84545e79557977c0600c46e": {
    "id": "trumpeffect69420",
    "circulating_supply": 47000000.0
  },
  "0xdc9cb148ecb70876db0abeb92f515a5e1dc9f580": {
    "id": "green-bitcoin",
    "circulating_supply": 0.0
  },
  "0x8c1bed5b9a0928467c9b1341da1d7bd5e10b6549": {
    "id": "liquid-staked-ethereum",
    "circulating_supply": 333704.5589436453
  },
  "0x8ce9137d39326ad0cd6491fb5cc0cba0e089b6a9": {
    "id": "swipe",
    "circulating_supply": 655170869.9034001
  },
  "0x7e4c9923fd8f18442532a737365c1bfb52579d2f": {
    "id": "arcadiaos",
    "circulating_supply": 1000000000.0
  },
  "0xc71b5f631354be6853efe9c3ab6b9590f8302e81": {
    "id": "polyhedra-network",
    "circulating_supply": 354972223.0
  },
  "0xe4b4c008ff36e3c50c4299c223504a480de9c833": {
    "id": "secret-society",
    "circulating_supply": 0.0
  },
  "0x164f12c8d7d16b905cc4f11e819a9fc5b183ef71": {
    "id": "dmarketplace",
    "circulating_supply": 91999997035.83809
  },
  "0xfc21540d6b89667d167d42086e1feb04da3e9b21": {
    "id": "infinite-2",
    "circulating_supply": 0.0
  },
  "0xdf87270e04bc5ac140e93571d0dd0c6f4a058b41": {
    "id": "moolahverse",
    "circulating_supply": 267567394.9992
  },
  "0x5027fc44a7ba114b8f494b1e4970900c6652fedf": {
    "id": "arcana-token",
    "circulating_supply": 612091804.77218
  },
  "0xbf358f7023d6fd0d11ac284eb47b877c1af635aa": {
    "id": "archeriumai",
    "circulating_supply": 100000000.0
  },
  "0xb624960aaad05d433075a5c9e760adec26036934": {
    "id": "monke-coin-eth",
    "circulating_supply": 0.0
  },
  "0x30ae41d5f9988d359c733232c6c693c0e645c77e": {
    "id": "wrapped-ayeayecoin",
    "circulating_supply": 6000000.0
  },
  "0x07040971246a73ebda9cf29ea1306bb47c7c4e76": {
    "id": "american-pepe",
    "circulating_supply": 0.0
  },
  "0x8f693ca8d21b157107184d29d398a8d082b38b76": {
    "id": "streamr",
    "circulating_supply": 767121867.0
  },
  "0x7316d973b0269863bbfed87302e11334e25ea565": {
    "id": "ken",
    "circulating_supply": 1000000000.0
  },
  "0x0018d5e01e53878f90feab02f1b2019a21adf8b1": {
    "id": "shadowcats",
    "circulating_supply": 0.0
  },
  "0x6368e1e18c4c419ddfc608a0bed1ccb87b9250fc": {
    "id": "tap",
    "circulating_supply": 3777481820.34
  },
  "0x115ec79f1de567ec68b7ae7eda501b406626478e": {
    "id": "carry",
    "circulating_supply": 10000000000.0
  },
  "0x48d41fc014865c32be82c50ee647b6a4bfab38a8": {
    "id": "kumaneene",
    "circulating_supply": 1000000000000000.0
  },
  "0x5b7533812759b45c2b44c19e320ba2cd2681b542": {
    "id": "singularitynet",
    "circulating_supply": 291373119.9776824
  },
  "0x27c78a7c10a0673c3509ccf63044aab92e09edac": {
    "id": "butterfly-ai",
    "circulating_supply": 10000000.0
  },
  "0xfab13732ae25267a5f47f6f31660c9a82b5fa9f1": {
    "id": "skibidi-dop-dop",
    "circulating_supply": 761512552.62
  },
  "0x901a020915bc3577d85d29f68024b4c5e240b8cd": {
    "id": "blastup",
    "circulating_supply": 0.0
  },
  "0x243cacb4d5ff6814ad668c3e225246efa886ad5a": {
    "id": "shina-inu",
    "circulating_supply": 14019639368119.16
  },
  "0x4ad434b8cdc3aa5ac97932d6bd18b5d313ab0f6f": {
    "id": "evermoon-erc",
    "circulating_supply": 0.0
  },
  "0xb939da54f9748440a1b279d42be1296942732288": {
    "id": "fonzy",
    "circulating_supply": 0.0
  },
  "0x19f78a898f3e3c2f40c6e0cd2ee5545f549d5e99": {
    "id": "deputy-dawgs",
    "circulating_supply": 313000000000.0
  },
  "0xcab254f1a32343f11ab41fbde90ecb410cde348a": {
    "id": "frogevip",
    "circulating_supply": 649675271791611.8
  },
  "0x53206bf5b6b8872c1bb0b3c533e06fde2f7e22e4": {
    "id": "blepe",
    "circulating_supply": 1000000000.0
  },
  "0x404d3295c8b1c61662068db584125a7ebcc0d651": {
    "id": "mambo",
    "circulating_supply": 1000000000000.0
  },
  "0xedc3be0080f65c628964f44ba3f2b6057e60f8dc": {
    "id": "dash-2",
    "circulating_supply": 1000000000.0
  },
  "0x9727eaf447203be268e5d471b6503bf47a71ea72": {
    "id": "arky",
    "circulating_supply": 0.0
  },
  "0x58d97b57bb95320f9a05dc918aef65434969c2b2": {
    "id": "morpho",
    "circulating_supply": 331414687.0431407
  },
  "0x2fb652314c3d850e9049057bbe9813f1eee882d3": {
    "id": "rocketx",
    "circulating_supply": 96453508.00044392
  },
  "0x71fc1f555a39e0b698653ab0b475488ec3c34d57": {
    "id": "rainmaker-games",
    "circulating_supply": 444474338.7919175
  },
  "0xbdc7c08592ee4aa51d06c27ee23d5087d65adbcd": {
    "id": "lift-dollar",
    "circulating_supply": 50913664.95180171
  },
  "0xed0439eacf4c4965ae4613d77a5c2efe10e5f183": {
    "id": "shroom-finance",
    "circulating_supply": 51386058.26854872
  },
  "0xcff252a3299be44fa73402966f30a0159308b2ad": {
    "id": "envoy-a-i",
    "circulating_supply": 879142815.9875679
  },
  "0x809b05ff167c7d70425951753bc0eb0fcc8e491f": {
    "id": "callofmeme",
    "circulating_supply": 1000000000.0
  },
  "0x0f71b8de197a1c84d31de0f1fa7926c365f052b3": {
    "id": "arcona",
    "circulating_supply": 15181707.0
  },
  "0xd4e245848d6e1220dbe62e155d89fa327e43cb06": {
    "id": "aave-v3-frax",
    "circulating_supply": 0.0
  },
  "0x283d480dfd6921055e9c335fc177bf8cb9c94184": {
    "id": "vix777",
    "circulating_supply": 1000000000.0
  },
  "0x766d2fcece1e3eef32aae8711ab886ee95fd5b2a": {
    "id": "maga-vp",
    "circulating_supply": 45253704.5339587
  },
  "0x3e43efbfa058d351a926fc611e997f2338adc2a4": {
    "id": "origent-ai",
    "circulating_supply": 98000000.0
  },
  "0x2f5fa8adf5f09a5f9de05b65fe82a404913f02c4": {
    "id": "troll-2-0",
    "circulating_supply": 0.0
  },
  "0x15b543e986b8c34074dfc9901136d9355a537e7e": {
    "id": "student-coin",
    "circulating_supply": 0.0
  },
  "0xa02c49da76a085e4e1ee60a6b920ddbc8db599f4": {
    "id": "shiba-inu-treat",
    "circulating_supply": 2151626009.4061875
  },
  "0x0026dfbd8dbb6f8d0c88303cc1b1596409fda542": {
    "id": "sanshu",
    "circulating_supply": 1000000000.0
  },
  "0x6f40d4a6237c257fff2db00fa0510deeecd303eb": {
    "id": "instadapp",
    "circulating_supply": 76753292.53490426
  },
  "0x445bd590a01fe6709d4f13a8f579c1e4846921db": {
    "id": "dummy",
    "circulating_supply": 0.0
  },
  "0x5d3a536e4d6dbd6114cc1ead35777bab948e3643": {
    "id": "cdai",
    "circulating_supply": 983320611.3958731
  },
  "0xadd39272e83895e7d3f244f696b7a25635f34234": {
    "id": "pepe-unchained",
    "circulating_supply": 0.0
  },
  "0x777172d858dc1599914a1c4c6c9fc48c99a60990": {
    "id": "solidlydex",
    "circulating_supply": 12865424.34515476
  },
  "0x68449870eea84453044bd430822827e21fd8f101": {
    "id": "zaibot",
    "circulating_supply": 18960803.204090644
  },
  "0xd528cf2e081f72908e086f8800977df826b5a483": {
    "id": "paribus",
    "circulating_supply": 7511811271.627442
  },
  "0x5b1d655c93185b06b00f7925791106132cb3ad75": {
    "id": "darkmatter",
    "circulating_supply": 0.0
  },
  "0xfa63503f9e61fd59cbea137c122fa55c2daff14a": {
    "id": "litas",
    "circulating_supply": 4500000.0
  },
  "0xcf9560b9e952b195d408be966e4f6cf4ab8206e5": {
    "id": "doctor-evil",
    "circulating_supply": 0.0
  },
  "0x94a21565c923d2f75b3fcef158960a8b7e6ed07d": {
    "id": "merchminter",
    "circulating_supply": 915668729.1051433
  },  "0x4f311c430540db1d64e635eb55f969f1660b2016": {
    "id": "pepe-chain-2",
    "circulating_supply": 0.0
  },
  "0xfe0c30065b384f05761f15d0cc899d4f9f9cc0eb": {
    "id": "ether-fi",
    "circulating_supply": 466326460.0
  },
  "0x6942040b6d25d6207e98f8e26c6101755d67ac89": {
    "id": "mellow-man",
    "circulating_supply": 69420000.0
  },
  "0x033bbde722ea3cdcec73cffea6581df9f9c257de": {
    "id": "velar",
    "circulating_supply": 330690228.920179
  },
  "0xccc8cb5229b0ac8069c51fd58367fd1e622afd97": {
    "id": "gods-unchained",
    "circulating_supply": 394027780.0649
  },
  "0xf9902edfca4f49dcaebc335c73aebd82c79c2886": {
    "id": "ado-network",
    "circulating_supply": 400000000.0
  },
  "0x2b591e99afe9f32eaa6214f7b7629768c40eeb39": {
    "id": "hex",
    "circulating_supply": 0.0
  },
  "0xc9eb61ffb66d5815d643bbb8195e17c49687ae1e": {
    "id": "morpheus-labs",
    "circulating_supply": 2100000000.0
  },
  "0xe60779cc1b2c1d0580611c526a8df0e3f870ec48": {
    "id": "unsheth",
    "circulating_supply": 47875310.114787586
  },
  "0xe5b826ca2ca02f09c1725e9bd98d9a8874c30532": {
    "id": "zeon",
    "circulating_supply": 0.0
  },
  "0xc28eb2250d1ae32c7e74cfb6d6b86afc9beb6509": {
    "id": "open-ticketing-ecosystem",
    "circulating_supply": 22926928000.0
  },
  "0xddbcdd8637d5cedd15eeee398108fca05a71b32b": {
    "id": "cryptify-ai",
    "circulating_supply": 1000000000.0
  },
  "0x32b86b99441480a7e5bd3a26c124ec2373e3f015": {
    "id": "bad-idea-ai",
    "circulating_supply": 684828903150833.0
  },
  "0x0b0a8c7c34374c1d0c649917a97eee6c6c929b1b": {
    "id": "shiba-v-pepe",
    "circulating_supply": 0.0
  },
  "0xd502f487e1841fdc805130e13eae80c61186bc98": {
    "id": "integral",
    "circulating_supply": 83940562.3466514
  },
  "0x46305b2ebcd92809d5fcef577c20c28a185af03c": {
    "id": "shadowladys-dn404",
    "circulating_supply": 0.0
  },
  "0x4fe83213d56308330ec302a8bd641f1d0113a4cc": {
    "id": "nucypher",
    "circulating_supply": 0.0
  },
  "0xb624fde1a972b1c89ec1dad691442d5e8e891469": {
    "id": "sporkdao",
    "circulating_supply": 0.0
  },
  "0xdae0fafd65385e7775cf75b1398735155ef6acd2": {
    "id": "truth",
    "circulating_supply": 0.0
  },
  "0x661013bb8d1c95d86d9c85f76e9004561f1bb36f": {
    "id": "defi-robot",
    "circulating_supply": 0.0
  },
  "0xd843713a7e6b3627cca4e7f70d34318d72708152": {
    "id": "furo",
    "circulating_supply": 997674575.7383333
  },
  "0x6d06426a477200c385843a9ac4d4fd55346f2b7b": {
    "id": "ginnan-neko",
    "circulating_supply": 1000000000000000.0
  },
  "0x990f341946a3fdb507ae7e52d17851b87168017c": {
    "id": "strong",
    "circulating_supply": 399818.3293437359
  },
  "0x80795a7bb55f003b1572411a271e31f73e03dd73": {
    "id": "daumenfrosch-2",
    "circulating_supply": 0.0
  },
  "0xf9fb4ad91812b704ba883b11d2b576e890a6730a": {
    "id": "aave-amm-weth",
    "circulating_supply": 0.0
  },
  "0x00869e8e2e0343edd11314e6ccb0d78d51547ee5": {
    "id": "supergrok",
    "circulating_supply": 1000000000.0
  },
  "0xbddc20ed7978b7d59ef190962f441cd18c14e19f": {
    "id": "crypto-asset-governance-alliance",
    "circulating_supply": 62805053924.83529
  },
  "0x2da719db753dfa10a62e140f436e1d67f2ddb0d6": {
    "id": "cere-network",
    "circulating_supply": 6637897251.424108
  },
  "0x9cf0ed013e67db12ca3af8e7506fe401aa14dad6": {
    "id": "spectre-ai",
    "circulating_supply": 9993171.20242279
  },
  "0xd3fd63209fa2d55b07a0f6db36c2f43900be3094": {
    "id": "wrapped-savings-rusd",
    "circulating_supply": 22427597.66256074
  },
  "0xd85a6ae55a7f33b0ee113c234d2ee308edeaf7fd": {
    "id": "cobak-token",
    "circulating_supply": 96751361.0
  },
  "0x6e9730ecffbed43fd876a264c982e254ef05a0de": {
    "id": "nord-finance",
    "circulating_supply": 7394582.383514433
  },
  "0x0f7dc5d02cc1e1f5ee47854d534d332a1081ccc8": {
    "id": "pepes-dog",
    "circulating_supply": 420690000000000.0
  },
  "0x362033a25b37603d4c99442501fa7b2852ddb435": {
    "id": "matrix-3",
    "circulating_supply": 100000000000.0
  },
  "0x378e1be15be6d6d1f23cfe7090b6a77660dbf14d": {
    "id": "foxe",
    "circulating_supply": 0.0
  },
  "0xcb69e5750f8dc3b69647b9d8b1f45466ace0a027": {
    "id": "xiaobai",
    "circulating_supply": 1000000000000000.0
  },
  "0xf7554eac0bf20d702e69d08c425e817abb976aea": {
    "id": "make-america-healthy-again",
    "circulating_supply": 10000000000.0
  },
  "0xa5c45d48d36607741e90c0cca29545a46f5ee121": {
    "id": "chiba-wan",
    "circulating_supply": 200000000000.0
  },
  "0xce872db165d4f5623af9c29e03afd416bc5f67bc": {
    "id": "stakevault-network",
    "circulating_supply": 0.0
  },
  "0x5a666c7d92e5fa7edcb6390e4efd6d0cdd69cf37": {
    "id": "unmarshal",
    "circulating_supply": 63342378.860617556
  },
  "0xa1e349fac47e50b42cd323c4285ef4622b60a5e0": {
    "id": "pepy-coin",
    "circulating_supply": 0.0
  },
  "0xb5c5fc6d3576ae31b24dc18e5bcb8a4822f13333": {
    "id": "whaleai",
    "circulating_supply": 1000000.0
  },
  "0xd88611a629265c9af294ffdd2e7fa4546612273e": {
    "id": "mpro-lab",
    "circulating_supply": 17016646.18147702
  },
  "0x9d1a74967eca155782edf8e84782c74db33fc499": {
    "id": "ai-com",
    "circulating_supply": 0.0
  },
  "0x808688c820ab080a6ff1019f03e5ec227d9b522b": {
    "id": "bag",
    "circulating_supply": 5934874908.056066
  },
  "0x450e7f6e3a2f247a51b98c39297a9a5bfbdb3170": {
    "id": "elon-goat",
    "circulating_supply": 0.0
  },
  "0xb87b96868644d99cc70a8565ba7311482edebf6e": {
    "id": "onchain-pepe-404",
    "circulating_supply": 88.0
  },
  "0xd1b5651e55d4ceed36251c61c50c889b36f6abb5": {
    "id": "stake-dao-crv",
    "circulating_supply": 0.0
  },
  "0x8e0fe2947752be0d5acf73aae77362daf79cb379": {
    "id": "nftrade",
    "circulating_supply": 46584184.0063241
  },
  "0xe79031b5aaeb3ee8d0145e3d75b81b36bffe341d": {
    "id": "boppy-the-bat",
    "circulating_supply": 420690000000000.0
  },
  "0x5caf454ba92e6f2c929df14667ee360ed9fd5b26": {
    "id": "dev-protocol",
    "circulating_supply": 2612113.5710242186
  },
  "0x5de597849cf72c72f073e9085bdd0dadd8e6c199": {
    "id": "finblox",
    "circulating_supply": 4796033690.379
  },
  "0xf4172630a656a47ece8616e75791290446fa41a0": {
    "id": "peppa",
    "circulating_supply": 0.0
  },
  "0x1cc7047e15825f639e0752eb1b89e4225f5327f2": {
    "id": "pullix",
    "circulating_supply": 0.0
  },
  "0x6fd46112c8ec76e7940dbfdc150774ee6eff27b2": {
    "id": "runner-on-eth",
    "circulating_supply": 1000000000.0
  },
  "0xc06caead870d3a8af2504637b6c5b7248bed6116": {
    "id": "business-coin",
    "circulating_supply": 949973142.65894
  },
  "0x1a57367c6194199e5d9aea1ce027431682dfb411": {
    "id": "matrixetf",
    "circulating_supply": 41600000.0
  },
  "0x4dfae3690b93c47470b03036a17b23c1be05127c": {
    "id": "pepe-2",
    "circulating_supply": 37321.21831358988
  },
  "0x65b3f4a4694b125ada8f9ebc2b79d6c7d4015d1b": {
    "id": "steam22",
    "circulating_supply": 100000000.0
  },
  "0xfc60fc0145d7330e5abcfc52af7b043a1ce18e7d": {
    "id": "gvnr",
    "circulating_supply": 11957048.24
  },
  "0xbef26bd568e421d6708cca55ad6e35f8bfa0c406": {
    "id": "bitscrunch-token",
    "circulating_supply": 575476022.9954585
  },
  "0xab93df617f51e1e415b5b4f8111f122d6b48e55c": {
    "id": "delta-exchange-token",
    "circulating_supply": 94423793.64346012
  },
  "0xa21af1050f7b26e0cff45ee51548254c41ed6b5c": {
    "id": "osaka-protocol",
    "circulating_supply": 761459784660251.2
  },
  "0xf4d861575ecc9493420a3f5a14f85b13f0b50eb3": {
    "id": "fractal",
    "circulating_supply": 122570430.62661351
  },
  "0x71fc860f7d3a592a4a98740e39db31d25db65ae8": {
    "id": "aave-usdt-v1",
    "circulating_supply": 0.0
  },
  "0xbe92b510007bd3ec0adb3d1fca338dd631e98de7": {
    "id": "degenstogether",
    "circulating_supply": 0.0
  },
  "0xbb126042235e6bd38b17744cb31a8bf4a206c045": {
    "id": "fanc",
    "circulating_supply": 0.0
  },
  "0xb0ffa8000886e57f86dd5264b9582b2ad87b2b91": {
    "id": "wormhole",
    "circulating_supply": 4754655333.0
  },
  "0x66d79b8f60ec93bfce0b56f5ac14a2714e509a99": {
    "id": "marcopolo",
    "circulating_supply": 6029780372.237291
  },
  "0x1776b223ff636d0d76adf2290821f176421dd889": {
    "id": "america1776",
    "circulating_supply": 0.0
  },
  "0xfe2e637202056d30016725477c5da089ab0a043a": {
    "id": "seth2",
    "circulating_supply": 2230.825741459874
  },
  "0x80810a9c31e7243a0bfb9919b0b4020378d1c134": {
    "id": "the-republican-party",
    "circulating_supply": 8081000000.0
  },
  "0xd721706581d97ecd202bbab5c71b5a85f0f78e69": {
    "id": "doge-1",
    "circulating_supply": 1000000.0
  },
  "0x249e38ea4102d0cf8264d3701f1a0e39c4f2dc3b": {
    "id": "ufo-gaming",
    "circulating_supply": 25757575757575.0
  },
  "0x4cd0c43b0d53bc318cc5342b77eb6f124e47f526": {
    "id": "freerossdao",
    "circulating_supply": 7716753607.35489
  },
  "0xa8b12cc90abf65191532a12bb5394a714a46d358": {
    "id": "pbtc35a",
    "circulating_supply": 214601.99998208
  },
  "0x48c276e8d03813224bb1e55f953adb6d02fd3e02": {
    "id": "kuma-inu",
    "circulating_supply": 399023779178324.06
  },
  "0x8dd09822e83313adca54c75696ae80c5429697ff": {
    "id": "sifu-vision-2",
    "circulating_supply": 0.0
  },
  "0x2a414884a549ef5716bc1a4e648d3dc03f08b2cf": {
    "id": "perq",
    "circulating_supply": 582761832.9654185
  },
  "0xd1f2586790a5bd6da1e443441df53af6ec213d83": {
    "id": "ledger-ai",
    "circulating_supply": 2152923343.599149
  },
  "0x98968f0747e0a261532cacc0be296375f5c08398": {
    "id": "mooncat-vault-nftx",
    "circulating_supply": 0.0
  },
  "0x04c154b66cb340f3ae24111cc767e0184ed00cc6": {
    "id": "dinero-staked-eth",
    "circulating_supply": 0.0
  },
  "0x420b879b0d18cc182e7e82ad16a13877c3a88420": {
    "id": "big-bud",
    "circulating_supply": 0.0
  },
  "0x005e6fd1610302018dcd9caf29b8bc38ff6efd98": {
    "id": "metafox",
    "circulating_supply": 10000000000.0
  },
  "0x40e5a14e1d151f34fea6b8e6197c338e737f9bf2": {
    "id": "valinity",
    "circulating_supply": 11549128.730726201
  },
  "0x391cf4b21f557c935c7f670218ef42c21bd8d686": {
    "id": "morphware",
    "circulating_supply": 780582622.2736651
  },
  "0xe1c8d908f0e495cf6d8459547d1d28b72bf04bf2": {
    "id": "tesseractai",
    "circulating_supply": 0.0
  },
  "0xc67b12049c2d0cf6e476bc64c7f82fc6c63cffc5": {
    "id": "globe-derivative-exchange",
    "circulating_supply": 0.0
  },
  "0xeeb4d8400aeefafc1b2953e0094134a887c76bd8": {
    "id": "avail",
    "circulating_supply": 3475326155.0
  },
  "0x2596825a84888e8f24b747df29e11b5dd03c81d7": {
    "id": "faith-tribe",
    "circulating_supply": 2697106751.05
  },
  "0x69cbaf6c147086c3c234385556f8a0c6488d3420": {
    "id": "69420",
    "circulating_supply": 62502297000.0
  },
  "0xe1d7c7a4596b038ced2a84bf65b8647271c53208": {
    "id": "nfty-token",
    "circulating_supply": 556620633.0
  },
  "0x91fbb2503ac69702061f1ac6885759fc853e6eae": {
    "id": "k9-finance-dao",
    "circulating_supply": 682786067095.4242
  },
  "0x108a850856db3f85d0269a2693d896b394c80325": {
    "id": "thorwallet",
    "circulating_supply": 588019975.9044309
  },
  "0x21cd589a989615a9e901328d3c089bbca16d00b2": {
    "id": "x-money",
    "circulating_supply": 10000000.0
  },
  "0x4a467232abe1472f9abeb49dcd2b34590222cae9": {
    "id": "grid-protocol",
    "circulating_supply": 770000000.0
  },
  "0xc114d80a2a188f30400b3cd545c5e296f0b04c3f": {
    "id": "rita-elite-order",
    "circulating_supply": 100000000.0
  },
  "0xa92e7c82b11d10716ab534051b271d2f6aef7df5": {
    "id": "ara-token",
    "circulating_supply": 736482152.3647218
  },
  "0xabd4c63d2616a5201454168269031355f4764337": {
    "id": "orderly-network",
    "circulating_supply": 296119502.3445693
  },
  "0x69bb12b8ee418e4833b8debe4a2bb997ab9ce18e": {
    "id": "mohameme-bit-salman",
    "circulating_supply": 0.0
  },  "0x807534b396919783b7e30383fe57d857bc084338": {
    "id": "test-2",
    "circulating_supply": 0.0
  },
  "0x57b96d4af698605563a4653d882635da59bf11af": {
    "id": "rch-token",
    "circulating_supply": 26829510.26995546
  },
  "0xf938346d7117534222b48d09325a6b8162b3a9e7": {
    "id": "choppy",
    "circulating_supply": 0.0
  },
  "0x798bcb35d2d48c8ce7ef8171860b8d53a98b361d": {
    "id": "meta-pool",
    "circulating_supply": 0.0
  },
  "0xa562912e1328eea987e04c2650efb5703757850c": {
    "id": "drops",
    "circulating_supply": 0.0
  },
  "0x055999b83f9cade9e3988a0f34ef72817566800d": {
    "id": "bbs-network",
    "circulating_supply": 548487339.0
  },
  "0x24c19f7101c1731b85f1127eaa0407732e36ecdd": {
    "id": "sharedstake-governance-token",
    "circulating_supply": 2715631.0
  },
  "0xf4c0efc13ea4221ad8278fb53727015471dce938": {
    "id": "sp500-token",
    "circulating_supply": 325000000.0
  },
  "0xcccccccccc33d538dbc2ee4feab0a7a1ff4e8a94": {
    "id": "centrifuge-2",
    "circulating_supply": 564842824.0
  },
  "0xf6ce4be313ead51511215f1874c898239a331e37": {
    "id": "bird-dog",
    "circulating_supply": 420690000000.0
  },
  "0x590830dfdf9a3f68afcdde2694773debdf267774": {
    "id": "giza",
    "circulating_supply": 146917280.8042542
  },
  "0x525536d71848f21b66da0d239546c50ee4c1a358": {
    "id": "crypto-task-force",
    "circulating_supply": 420690000000.0
  },
  "0xf3e66b03d098d0482be9cb3d6999787231a93ed9": {
    "id": "promptide",
    "circulating_supply": 0.0
  },
  "0x2ef52ed7de8c5ce03a4ef0efbe9b7450f2d7edc9": {
    "id": "revain",
    "circulating_supply": 184551367443.6664
  },
  "0x4168bbc34baea34e55721809911bca5baaef6ba6": {
    "id": "dodreamchain",
    "circulating_supply": 180106239.0
  },
  "0x9e10f61749c4952c320412a6b26901605ff6da1d": {
    "id": "theos",
    "circulating_supply": 0.0
  },
  "0x2efa572467c50c04a6eed6742196c0d0d287c1bb": {
    "id": "based-chad",
    "circulating_supply": 69420000000.0
  },
  "0xde4ee8057785a7e8e800db58f9784845a5c2cbd6": {
    "id": "dexe",
    "circulating_supply": 57103774.56313077
  },
  "0x50d5118fb90d572b9d42ba65e0addc4900867809": {
    "id": "osean",
    "circulating_supply": 849848136.7760828
  },
  "0x8a7b7b9b2f7d0c63f66171721339705a6188a7d5": {
    "id": "etherdoge",
    "circulating_supply": 0.0
  },
  "0x7eeab3de47a475fd2dec438aef05b128887c6105": {
    "id": "troppy",
    "circulating_supply": 420689999999.9999
  },
  "0xe53ec727dbdeb9e2d5456c3be40cff031ab40a55": {
    "id": "superfarm",
    "circulating_supply": 628414545.0
  },
  "0x2b37127988e4e5e9576b7a533d873c23cfbdb1e9": {
    "id": "zentium-tech",
    "circulating_supply": 10000000.0
  },
  "0x038a68ff68c393373ec894015816e33ad41bd564": {
    "id": "glitch-protocol",
    "circulating_supply": 70140711.61081402
  },
  "0x1b3be8fcd2e7c5ce9c5c242e0066fdd9740220d0": {
    "id": "licker",
    "circulating_supply": 970000000.0
  },
  "0x522ec96bced6dc26325120edf3931d34e417a620": {
    "id": "market-stalker",
    "circulating_supply": 100000000.0
  },
  "0x22b6c31c2beb8f2d0d5373146eed41ab9ede3caf": {
    "id": "cocktailbar",
    "circulating_supply": 50000.0
  },
  "0x7c1156e515aa1a2e851674120074968c905aaf37": {
    "id": "level-usd",
    "circulating_supply": 39516729.89462978
  },
  "0xbe0ed4138121ecfc5c0e56b40517da27e6c5226b": {
    "id": "aethir",
    "circulating_supply": 11407789036.0
  },
  "0x85eee30c52b0b379b046fb0f85f4f3dc3009afec": {
    "id": "keep-network",
    "circulating_supply": 549716300.2685891
  },
  "0x7a4effd87c2f3c55ca251080b1343b605f327e3a": {
    "id": "restaking-vault-eth",
    "circulating_supply": 38168.52985148088
  },
  "0xf2dfdbe1ea71bbdcb5a4662a16dbf5e487be3ebe": {
    "id": "decloud",
    "circulating_supply": 0.0
  },
  "0x3bb1be077f3f96722ae92ec985ab37fd0a0c4c51": {
    "id": "marv",
    "circulating_supply": 420690000000000.0
  },
  "0x1010107b4757c915bc2f1ecd08c85d1bb0be92e0": {
    "id": "brain-frog",
    "circulating_supply": 10000000.0
  },
  "0x33e07f5055173cf8febede8b21b12d1e2b523205": {
    "id": "etherland",
    "circulating_supply": 40883405.41270585
  },
  "0x149af500734056b98572b66e6c771e57408e12e4": {
    "id": "horizon-4",
    "circulating_supply": 8581307.002004618
  },
  "0x668c50b1c7f46effbe3f242687071d7908aab00a": {
    "id": "coshi-inu",
    "circulating_supply": 0.0
  },
  "0x3850952491606a0e420eb929b1a2e1a450d013f1": {
    "id": "panoverse",
    "circulating_supply": 28000000.0
  },
  "0xd2bdaaf2b9cc6981fd273dcb7c04023bfbe0a7fe": {
    "id": "aviator",
    "circulating_supply": 6974001366.81491
  },
  "0x39fbbabf11738317a448031930706cd3e612e1b9": {
    "id": "wrapped-xrp",
    "circulating_supply": 17947559.108324
  },
  "0x8c6bf16c273636523c29db7db04396143770f6a0": {
    "id": "moon-rabbit",
    "circulating_supply": 0.0
  },
  "0x77146784315ba81904d654466968e3a7c196d1f3": {
    "id": "treehouse",
    "circulating_supply": 156122449.0
  },
  "0xbabe3ce7835665464228df00b03246115c30730a": {
    "id": "baby-neiro-token",
    "circulating_supply": 420690000000.0
  },
  "0x06b964d96f5dcf7eae9d7c559b09edce244d4b8e": {
    "id": "usualx",
    "circulating_supply": 498023228.559568
  },
  "0xd69a0a9682f679f50e34de40105a93bebb2ff43d": {
    "id": "mackerel-2",
    "circulating_supply": 1675265.1472124741
  },
  "0x42069f39c71816cea208451598425b492dd2b380": {
    "id": "goompy",
    "circulating_supply": 420690000000.0
  },
  "0xb6ca7399b4f9ca56fc27cbff44f4d2e4eef1fc81": {
    "id": "muse-2",
    "circulating_supply": 829127.4726336007
  },
  "0x320ed4c7243e35a00f9ca30a1ae60929d15eae37": {
    "id": "the-blox-project",
    "circulating_supply": 0.0
  },
  "0xfcf7985661d2c3f62208970cbe25e70bcce73e7c": {
    "id": "rwa-ai",
    "circulating_supply": 0.0
  },
  "0xe5097d9baeafb89f9bcb78c9290d545db5f9e9cb": {
    "id": "hummingbot",
    "circulating_supply": 553268062.0208296
  },
  "0xaa4e3edb11afa93c41db59842b29de64b72e355b": {
    "id": "marginswap",
    "circulating_supply": 7052147.880308889
  },
  "0xdc300854b0ef52650057158e8a33afe703525539": {
    "id": "betmore-casino",
    "circulating_supply": 1000000000.0
  },
  "0x3073f7aaa4db83f95e9fff17424f71d4751a3073": {
    "id": "movement",
    "circulating_supply": 2700000000.0
  },
  "0xd888a5460fffa4b14340dd9fe2710cbabd520659": {
    "id": "protokols",
    "circulating_supply": 10000000.0
  },
  "0x34df29dd880e9fe2cec0f85f7658b75606fb2870": {
    "id": "navy-seal",
    "circulating_supply": 0.0
  },
  "0x7c84e62859d0715eb77d1b1c4154ecd6abb21bec": {
    "id": "shping",
    "circulating_supply": 0.0
  },
  "0x6c6ee5e31d828de241282b9606c8e98ea48526e2": {
    "id": "holotoken",
    "circulating_supply": 177619433541.1413
  },
  "0xb62132e35a6c13ee1ee0f84dc5d40bad8d815206": {
    "id": "nexo",
    "circulating_supply": 1000000000.0
  },
  "0x464ebe77c293e473b48cfe96ddcf88fcf7bfdac0": {
    "id": "kryll",
    "circulating_supply": 39852368.60137463
  },
  "0x8400d94a5cb0fa0d041a3788e395285d61c9ee5e": {
    "id": "unibright",
    "circulating_supply": 150000000.0
  },
  "0xea26c4ac16d4a5a106820bc8aee85fd0b7b2b664": {
    "id": "quark-chain",
    "circulating_supply": 7159673559.0
  },
  "0xa849eaae994fb86afa73382e9bd88c2b6b18dc71": {
    "id": "mass-vehicle-ledger",
    "circulating_supply": 27202958863.10265
  },
  "0xd26114cd6ee289accf82350c8d8487fedb8a0c07": {
    "id": "omisego",
    "circulating_supply": 140245398.2451327
  },
  "0xb8c77482e45f1f44de1745f52c74426c631bdd52": {
    "id": "binancecoin",
    "circulating_supply": 139187222.12
  },
  "0x5d60d8d7ef6d37e16ebabc324de3be57f135e0bc": {
    "id": "mybit-token",
    "circulating_supply": 179998249.0
  },
  "0x0f8c45b896784a1e408526b9300519ef8660209c": {
    "id": "xmax",
    "circulating_supply": 27000000000.0
  },
  "0x4e15361fd6b4bb609fa63c81a2be19d873717870": {
    "id": "wrapped-fantom",
    "circulating_supply": 0.0
  },
  "0xdd16ec0f66e54d453e6756713e533355989040e4": {
    "id": "tokenomy",
    "circulating_supply": 115497435.0
  },
  "0x814e0908b12a99fecf5bc101bb5d0b8b5cdf7d26": {
    "id": "measurable-data-token",
    "circulating_supply": 606319736.1236151
  },
  "0x846c66cf71c43f80403b51fe3906b3599d63336f": {
    "id": "pumapay",
    "circulating_supply": 26476422230.56
  },
  "0x4a220e6096b25eadb88358cb44068a3248254675": {
    "id": "quant-network",
    "circulating_supply": 14544176.164091088
  },
  "0xa15c7ebe1f07caf6bff097d8a589fb8ac49ae5b3": {
    "id": "pundi-x",
    "circulating_supply": 236519288706.32507
  },
  "0x509a38b7a1cc0dcd83aa9d06214663d9ec7c7f4a": {
    "id": "blocksquare",
    "circulating_supply": 62712664.78864395
  },
  "0xdf2c7238198ad8b389666574f2d8bc411a4b7428": {
    "id": "mainframe",
    "circulating_supply": 9386552598.643353
  },
  "0xfc05987bd2be489accf0f509e44b0145d68240f7": {
    "id": "essentia",
    "circulating_supply": 1080572457.5912588
  },
  "0x93ed3fbe21207ec2e8f2d3c3de6e058cb73bc04d": {
    "id": "kleros",
    "circulating_supply": 724189581.4548858
  },
  "0x986ee2b944c42d017f52af21c4c69b84dbea35d8": {
    "id": "bitmart-token",
    "circulating_supply": 339412030.0
  },
  "0xc719d010b63e5bbf2c0551872cd5316ed26acd83": {
    "id": "etherisc",
    "circulating_supply": 383445510.60082114
  },
  "0x765f0c16d1ddc279295c1a7c24b0883f62d33f75": {
    "id": "databroker-dao",
    "circulating_supply": 225000000.0
  },
  "0xe50365f5d679cb98a1dd62d6f6e58e59321bcddf": {
    "id": "latoken",
    "circulating_supply": 60680000.0
  },
  "0xc64500dd7b0f1794807e67802f8abbf5f8ffb054": {
    "id": "locus-chain",
    "circulating_supply": 0.0
  },
  "0xff56cc6b1e6ded347aa0b7676c85ab0b3d08b0fa": {
    "id": "orbs",
    "circulating_supply": 4690772336.477301
  },
  "0xdac17f958d2ee523a2206206994597c13d831ec7": {
    "id": "tether",
    "circulating_supply": 169373054462.0727
  },
  "0x8f3470a7388c05ee4e7af3d01d8c722b0ff52374": {
    "id": "veritaseum",
    "circulating_supply": 0.0
  },
  "0xef53462838000184f35f7d991452e5f25110b207": {
    "id": "knit-finance",
    "circulating_supply": 50932953.95431276
  },
  "0xd47bdf574b4f76210ed503e0efe81b58aa061f3d": {
    "id": "dtravel",
    "circulating_supply": 449133520.0593805
  },
  "0x8e57c27761ebbd381b0f9d09bb92ceb51a358abb": {
    "id": "extradna",
    "circulating_supply": 0.0
  },
  "0x295b42684f90c77da7ea46336001010f2791ec8c": {
    "id": "xi-token",
    "circulating_supply": 421000000.0
  },
  "0xfe9a29ab92522d14fc65880d817214261d8479ae": {
    "id": "snowswap",
    "circulating_supply": 349663.9130302135
  },
  "0xcbd55d4ffc43467142761a764763652b48b969ff": {
    "id": "astrotools",
    "circulating_supply": 1983216.8391922219
  },
  "0xf1f508c7c9f0d1b15a76fba564eef2d956220cf7": {
    "id": "pepedex",
    "circulating_supply": 547379.254562628
  },
  "0x5cb3ce6d081fb00d5f6677d196f2d70010ea3f4a": {
    "id": "busy-dao",
    "circulating_supply": 255000000.0
  },
  "0xca9b8d6df0729d85dcfc8ef8bb18af1ad1990786": {
    "id": "catboy-3",
    "circulating_supply": 200000000.0
  },
  "0x5845684b49aef79a5c0f887f50401c247dca7ac6": {
    "id": "cycle-2",
    "circulating_supply": 152000000.0
  },
  "0x6985884c4392d348587b19cb9eaaf157f13271cd": {
    "id": "layerzero",
    "circulating_supply": 111152854.20763355
  },
  "0xa41f142b6eb2b164f8164cae0716892ce02f311f": {
    "id": "avaocado-dao",
    "circulating_supply": 148019207.95051312
  },
  "0x59f4f336bf3d0c49dbfba4a74ebd2a6ace40539a": {
    "id": "catcoin-cash",
    "circulating_supply": 3.449976944593045e+16
  },
  "0xa2e3356610840701bdf5611a53974510ae27e2e1": {
    "id": "wrapped-beacon-eth",
    "circulating_supply": 3164183.093000659
  },
  "0x22514ffb0d7232a56f0c24090e7b68f179faa940": {
    "id": "qopro",
    "circulating_supply": 443483341.75
  },
  "0x9840652dc04fb9db2c43853633f0f62be6f00f98": {
    "id": "chaingpt",
    "circulating_supply": 857188667.0
  },  "0xd48d639f72ef29458b72cdc9a47a95fa46101529": {
    "id": "helpkidz-coin",
    "circulating_supply": 0.0
  },
  "0xdc49a53e1f15fd7fd522e0691cb570f442e9ca6c": {
    "id": "quorium",
    "circulating_supply": 0.0
  },
  "0x124123c7af9efd2a86f4d41daa88ac164d02a3d5": {
    "id": "greenenvironmentalcoins",
    "circulating_supply": 0.0
  },
  "0x35de111558f691f77f791fb0c08b2d6b931a9d47": {
    "id": "chain-games",
    "circulating_supply": 379867524.57825387
  },
  "0x193f4a4a6ea24102f49b931deeeb931f6e32405d": {
    "id": "telos",
    "circulating_supply": 419999962.9645
  },
  "0x36f1f32c728c3f330409ec1f0928fa3ab3c8a76f": {
    "id": "adroverse",
    "circulating_supply": 0.0
  },
  "0x551faab1027cc50efaea5bed092e330475c3cd99": {
    "id": "monbasecoin",
    "circulating_supply": 189701480.0
  },
  "0x6067490d05f3cf2fdffc0e353b1f5fd6e5ccdf70": {
    "id": "market-making-pro",
    "circulating_supply": 92080754.82702632
  },
  "0xc58c1117da964aebe91fef88f6f5703e79bda574": {
    "id": "telebtc-2",
    "circulating_supply": 2.79578492
  },
  "0x4ff1f7ee6516dd1d14db83c2cbce06b69ad14444": {
    "id": "memecoin1",
    "circulating_supply": 1000000000.0
  },
  "0x261510dd6257494eea1dda7618dbe8a7b87870dd": {
    "id": "dehero-community-token",
    "circulating_supply": 0.0
  },
  "0x29132062319aa375e764ef8ef756f2b28c77a9c9": {
    "id": "blokpad",
    "circulating_supply": 0.0
  },
  "0x32d7da6a7cf25ed1b86e1b0ee9a62b0252d46b16": {
    "id": "ginza-network",
    "circulating_supply": 0.0
  },
  "0x9d0d41df4ca809dc16a9bff646d3c6cbc4ebc707": {
    "id": "rezor",
    "circulating_supply": 40985973127.90378
  },
  "0xb1957bdba889686ebde631df970ece6a7571a1b6": {
    "id": "defi-tiger",
    "circulating_supply": 358994946726578.1
  },
  "0x999e62f80d2c8ec8adfbf041b06239c6ae6d8492": {
    "id": "roomcon",
    "circulating_supply": 762501316.4071087
  },
  "0x5392ff4a9bd006dc272c1855af6640e17cc5ec0b": {
    "id": "safelaunch",
    "circulating_supply": 0.0
  },
  "0x9b208b117b2c4f76c1534b6f006b033220a681a4": {
    "id": "dingocoin",
    "circulating_supply": 107594400045.751
  },
  "0xe00e6919895929090c2d5342ae8375c169cf8888": {
    "id": "binants",
    "circulating_supply": 1000000000.0
  },
  "0x551897f8203bd131b350601d3ac0679ba0fc0136": {
    "id": "nfprompt-token",
    "circulating_supply": 503902467.2764947
  },
  "0x4db5a66e937a9f4473fa95b1caf1d1e1d62e29ea": {
    "id": "ethereum-wormhole",
    "circulating_supply": 0.0
  },
  "0x6ec90334d89dbdc89e08a133271be3d104128edb": {
    "id": "wiki-cat",
    "circulating_supply": 545657923518592.1
  },
  "0x963556de0eb8138e97a85f0a86ee0acd159d210b": {
    "id": "melega",
    "circulating_supply": 729766089.8324636
  },
  "0x8a74bc8c372bc7f0e9ca3f6ac0df51be15aec47a": {
    "id": "pulsepad",
    "circulating_supply": 170000000.0
  },
  "0x84f4f7cdb4574c9556a494dab18ffc1d1d22316c": {
    "id": "king-shiba",
    "circulating_supply": 296689140.9263628
  },
  "0x3fefe29da25bea166fb5f6ade7b5976d2b0e586b": {
    "id": "roam-token",
    "circulating_supply": 305814481.107417
  },
  "0xfd42728b76772a82ccad527e298dd15a55f4ddd6": {
    "id": "karencoin",
    "circulating_supply": 0.0
  },
  "0x94a8b4ee5cd64c79d0ee816f467ea73009f51aa0": {
    "id": "realio-network",
    "circulating_supply": 100000000.0
  },
  "0x12819623921be0f4d5ebfc12c75e6d08a1683080": {
    "id": "broccoli-2",
    "circulating_supply": 1000000000.0
  },
  "0xc08cd26474722ce93f4d0c34d16201461c10aa8c": {
    "id": "carv",
    "circulating_supply": 295209453.0
  },
  "0x9a26e6d24df036b0b015016d1b55011c19e76c87": {
    "id": "dragon-mainland-shards",
    "circulating_supply": 0.0
  },
  "0xc350caa89eb963d5d6b964324a0a7736d8d65533": {
    "id": "infinitee",
    "circulating_supply": 0.0
  },
  "0x968f6f898a6df937fc1859b323ac2f14643e3fed": {
    "id": "newscrypto-coin",
    "circulating_supply": 155377587.0
  },
  "0xbb1b031c591235408755ff4e0739cb88c5cf2507": {
    "id": "paal-ai",
    "circulating_supply": 897491580.7199504
  },
  "0x3ef144cb45c8a390eb207a6aa9bfcf3da639cb5c": {
    "id": "maga-coin",
    "circulating_supply": 202770536.79402897
  },
  "0x72a76965eb8f606675f119dae89deda557fdbf01": {
    "id": "eiqt-token",
    "circulating_supply": 0.0
  },
  "0x8fb238058e71f828f505582e65b1d14f8cf52067": {
    "id": "dar-open-network",
    "circulating_supply": 643112516.0
  },
  "0x2442421fe1acc8a732251fc372892b5ff1fdd938": {
    "id": "deer-token",
    "circulating_supply": 551575000.0
  },
  "0x6ccc8db8e3fd5ffdd2e7b92bd92e8e27baf704a8": {
    "id": "ethos-2",
    "circulating_supply": 0.0
  },
  "0xb003c68917bab76812797d1b8056822f48e2e4fe": {
    "id": "yummy",
    "circulating_supply": 0.0
  },
  "0x69df2aaea7a40dad19c74e65192df0d0f7f7912b": {
    "id": "alita-2",
    "circulating_supply": 0.0
  },
  "0x4e93bfcd6378e564c454bf99e130ae10a1c7b2dd": {
    "id": "airbtc",
    "circulating_supply": 0.0
  },
  "0xd9e90df21f4229249e8841580cde7048bf935710": {
    "id": "shield-protocol-3",
    "circulating_supply": 24344448.392937936
  },
  "0xdfa7e9c060dc5292c881eb48cfe26b27aef5f0d9": {
    "id": "bnbgpt",
    "circulating_supply": 0.0
  },
  "0x0e7779e698052f8fe56c415c3818fcf89de9ac6d": {
    "id": "ultiverse",
    "circulating_supply": 6515556655.0
  },
  "0x40f85d6040df96ea14cd41142bcd244e14cf76f6": {
    "id": "usd-coin-bridged-zed20",
    "circulating_supply": 0.0
  },
  "0xeee352f77f28d31601eb20d3de09d7729ca2dc79": {
    "id": "austin-capitals",
    "circulating_supply": 9786000.0
  },
  "0x841c1297f5485ecd72e7a9b62de5ef19f81c8af3": {
    "id": "dpin",
    "circulating_supply": 0.0
  },
  "0xa90298e5b1203a2dd0006a75eabe158989c406fb": {
    "id": "blue-protocol",
    "circulating_supply": 129099.239156378
  },
  "0x6b85f1fe36af537ce5085ef441c92de09af74f0e": {
    "id": "robotic-doge",
    "circulating_supply": 144520466384.0
  },
  "0x25382fb31e4b22e0ea09cb0761863df5ad97ed72": {
    "id": "paragen",
    "circulating_supply": 101252785.85118346
  },
  "0x61ec85ab89377db65762e234c946b5c25a56e99e": {
    "id": "htx-dao",
    "circulating_supply": 0.0
  },
  "0xa14b0b99c9117ea2f4fb2c9d772d95d9fd3acaab": {
    "id": "broccoli-5",
    "circulating_supply": 0.0
  },
  "0x9158df7da69b048a296636d5de7a3d9a7fb25e88": {
    "id": "kalijo",
    "circulating_supply": 1850352.0
  },
  "0x4ea98c1999575aaadfb38237dd015c5e773f75a2": {
    "id": "maga",
    "circulating_supply": 45018891.62567504
  },
  "0x6fd2854cd1b05b8eb5f6d25c714184a92fedaf4f": {
    "id": "o-megax",
    "circulating_supply": 750000000.0
  },
  "0xee7e8c85956d32c64bafdcded3f43b3c39b1ce2f": {
    "id": "web4-ai",
    "circulating_supply": 0.0
  },
  "0x6685906b75c61c57772c335402f594f855c1b0e3": {
    "id": "wilder-world",
    "circulating_supply": 394130764.03120714
  },
  "0x053708a5bc7f1627ddc87e780ee381cf1e31f765": {
    "id": "vela-ai",
    "circulating_supply": 0.0
  },
  "0x66207e39bb77e6b99aab56795c7c340c08520d83": {
    "id": "rupiah-token",
    "circulating_supply": 173856905811.0
  },
  "0x3b0e967ce7712ec68131a809db4f78ce9490e779": {
    "id": "souni-token",
    "circulating_supply": 0.0
  },
  "0x6ec9a568881755c9698384cc6b5b13bf4064e12b": {
    "id": "optimus-x",
    "circulating_supply": 1.994231654200326e+17
  },
  "0xa0cb0ce7c6d93a7ebd72952feb4407dddee8a194": {
    "id": "shibaken-finance",
    "circulating_supply": 0.0
  },
  "0x5f320c3b8f82acfe8f2bb1c85d63aa66a7ff524f": {
    "id": "nelore-coin",
    "circulating_supply": 323834230.76268065
  },
  "0x1bec41a36356d5574aeb068b599ab7e48dd008b8": {
    "id": "dogefood",
    "circulating_supply": 0.0
  },
  "0xd89336eac00e689d218c46cdd854585a09f432b3": {
    "id": "lusd-2",
    "circulating_supply": 0.0
  },
  "0x9cd9c5a44cb8fab39b2ee3556f5c439e65e4fddd": {
    "id": "mars4",
    "circulating_supply": 4000000000.0
  },
  "0xb01cf1be9568f09449382a47cd5bf58e2a9d5922": {
    "id": "lightspeed",
    "circulating_supply": 255362152.09239936
  },
  "0xffffff9936bd58a008855b0812b44d2c8dffe2aa": {
    "id": "good-game-us-dollar",
    "circulating_supply": 3582596.76195
  },
  "0xc9d23ed2adb0f551369946bd377f8644ce1ca5c4": {
    "id": "hyperlane",
    "circulating_supply": 175200000.0
  },
  "0xe215f9575e2fafff8d0d3f9c6866ac656bd25bd9": {
    "id": "ducky-2",
    "circulating_supply": 1000000000.0
  },
  "0x7c1941e49e388daf3d75ec2d187d49eca86392ea": {
    "id": "licko-2",
    "circulating_supply": 420690000000.0
  },
  "0x07c15e4add8c23d2971380dde6c57b6f88902ec1": {
    "id": "metamars-2",
    "circulating_supply": 166300000.0
  },
  "0x347862372f7c8f83d69025234367ac11c5241db3": {
    "id": "kiirocoin",
    "circulating_supply": 16425955.41655531
  },
  "0xf2b688b2201979d44fdf18d1d8c641305cf560ba": {
    "id": "devomon",
    "circulating_supply": 0.0
  },
  "0xf9752a6e8a5e5f5e6eb3ab4e7d8492460fb319f0": {
    "id": "ares-protocol",
    "circulating_supply": 295147020.43596286
  },
  "0x7f14ce2a5df31ad0d2bf658d3840b1f7559d3ee0": {
    "id": "nfstay",
    "circulating_supply": 0.0
  },
  "0xbb0fa2fbe9b37444f5d1dbd22e0e5bdd2afbbe85": {
    "id": "usd-mars",
    "circulating_supply": 0.0
  },
  "0xb700597d8425ced17677bc68042d7d92764acf59": {
    "id": "facedao",
    "circulating_supply": 0.0
  },
  "0xe138c66982fd5c890c60b94fdba1747faf092c20": {
    "id": "offshift",
    "circulating_supply": 10072791.006765
  },
  "0xac83271abb4ec95386f08ad2b904a46c61777cef": {
    "id": "nftrade",
    "circulating_supply": 46584184.0063241
  },
  "0xf2c88757f8d03634671208935974b60a2a28bdb3": {
    "id": "myshell",
    "circulating_supply": 270000000.0
  },
  "0x633237c6fa30fae46cc5bb22014da30e50a718cc": {
    "id": "defi-warrior",
    "circulating_supply": 2270639660.0
  },
  "0x90869b3a42e399951bd5f5ff278b8cc5ee1dc0fe": {
    "id": "revox",
    "circulating_supply": 2021659479.0
  },
  "0x537be31d47fbb697b36a098932cfc1343ac5f538": {
    "id": "baby-rudi",
    "circulating_supply": 3.7856771398903155e+17
  },
  "0x2598c30330d5771ae9f983979209486ae26de875": {
    "id": "any-inu",
    "circulating_supply": 420690000000.0
  },
  "0x9c27c4072738cf4b7b0b7071af0ad5666bddc096": {
    "id": "nianian",
    "circulating_supply": 948468317.6580948
  },
  "0x7b4bf9feccff207ef2cb7101ceb15b8516021acd": {
    "id": "milkyway-2",
    "circulating_supply": 260000000.0
  },
  "0x8888888809b788cd6e40a2d27e67425d5d0b5d3b": {
    "id": "changcoin",
    "circulating_supply": 0.0
  },
  "0xa18bbdcd86e4178d10ecd9316667cfe4c4aa8717": {
    "id": "bnbxbt",
    "circulating_supply": 1000000000.0
  },
  "0x34ba3af693d6c776d73c7fa67e2b2e79be8ef4ed": {
    "id": "shambala",
    "circulating_supply": 0.0
  },
  "0xcf10117b30c7a5fc7c77b611bfc2555610dd4b3a": {
    "id": "notai",
    "circulating_supply": 94999988888.5
  },
  "0xcd883a18f8d33cf823d13cf2c6787c913d09e640": {
    "id": "talentido",
    "circulating_supply": 0.0
  },
  "0x3e2242cb2fc1465822a0bb81ca2fe1f633a45757": {
    "id": "forky-2",
    "circulating_supply": 1000000000.0
  },
  "0x722294f6c97102fb0ddb5b907c8d16bdeab3f6d9": {
    "id": "doodles",
    "circulating_supply": 7800000000.0
  },
  "0x8ea5219a16c2dbf1d6335a6aa0c6bd45c50347c5": {
    "id": "openocean",
    "circulating_supply": 504525932.0
  },
  "0x8b4c03308579a0c4166b44f84565d97378303247": {
    "id": "madonna-del-gatto",
    "circulating_supply": 1000000000.0
  },
  "0x7f792db54b0e580cdc755178443f0430cf799aca": {
    "id": "volt-inu-2",
    "circulating_supply": 62263131613878.4
  },
  "0x518445f0db93863e5e93a7f70617c05afa8048f1": {
    "id": "bittoken",
    "circulating_supply": 9699610.0
  },
  "0x19be6f3f83d079d640720bda3b638a00a3b7ee20": {
    "id": "kitnet-token",
    "circulating_supply": 202117279.13363454
  },  "0x1236a887ef31b4d32e1f0a2b5e4531f52cec7e75": {
    "id": "gami-world",
    "circulating_supply": 43193899.0
  },
  "0xcbd9f6d748dd3d19416f8914528a65c7838e27d8": {
    "id": "r-games",
    "circulating_supply": 0.0
  },
  "0x2a17dc11a1828725cdb318e0036acf12727d27a2": {
    "id": "arena-token",
    "circulating_supply": 0.0
  },
  "0x921d3a6ed8223afb6358410f717e2fb13cbae700": {
    "id": "qrkita-token",
    "circulating_supply": 0.0
  },
  "0x4027d91ecd3140e53ae743d657549adfeebb27ab": {
    "id": "chain-of-legends",
    "circulating_supply": 68333235.0
  },
  "0x5651fa7a726b9ec0cad00ee140179912b6e73599": {
    "id": "oort",
    "circulating_supply": 591982576.5413383
  },
  "0x55ad16bd573b3365f43a9daeb0cc66a73821b4a5": {
    "id": "okzoo",
    "circulating_supply": 112516666.0
  },
  "0x1894251aebcff227133575ed3069be9670e25db0": {
    "id": "halo-coin",
    "circulating_supply": 5565659916.043767
  },
  "0x4823a096382f4fa583b55d563afb9f9a58c72fc0": {
    "id": "arabic",
    "circulating_supply": 0.0
  },
  "0xa856098dcbc1b2b3a9c96c35c32bc4f71e49aed2": {
    "id": "finceptor-token",
    "circulating_supply": 31367421.0
  },
  "0xe4e11e02aa14c7f24db749421986eaec1369e8c9": {
    "id": "minativerse",
    "circulating_supply": 5474999.0
  },
  "0xe3f53c0d48360de764ddc2a1a82c3e6db5d4624d": {
    "id": "emoneytoken",
    "circulating_supply": 136238682.2693632
  },
  "0x502a641decfe32b1e3d030e05effb8ae5146e64b": {
    "id": "palm-economy",
    "circulating_supply": 8103071152.523492
  },
  "0x07b36f2549291d320132712a1e64d3826b1fb4d7": {
    "id": "wifedoge",
    "circulating_supply": 0.0
  },
  "0xa53e61578ff54f1ad70186be99332a6e20b6ffa9": {
    "id": "golden-doge",
    "circulating_supply": 1e+17
  },
  "0x5e57f24415f37c7d304e85df9b4c36bc08789794": {
    "id": "barter",
    "circulating_supply": 783383.72258276
  },
  "0x8b9ee39195ea99d6ddd68030f44131116bc218f6": {
    "id": "peaq-2",
    "circulating_supply": 1183921224.194442
  },
  "0x121235cff4c59eec80b14c1d38b44e7de3a18287": {
    "id": "darkshield",
    "circulating_supply": 0.0
  },
  "0xfe2dd2d57a05f89438f3aec94eafa4070396bab0": {
    "id": "matchain",
    "circulating_supply": 7230000.0
  },
  "0xf3f3d7f713df0447e9595d9b830a5f00297070e4": {
    "id": "mother-earth",
    "circulating_supply": 0.0
  },
  "0x5b6ebb33eea2d12eefd4a9b2aeaf733231169684": {
    "id": "weld",
    "circulating_supply": 0.0
  },
  "0xceb24c99579e6140517d59c8dd4f5b36d84ed6de": {
    "id": "phecda",
    "circulating_supply": 0.0
  },
  "0x8182ac1c5512eb67756a89c40fadb2311757bd32": {
    "id": "nether",
    "circulating_supply": 0.0
  },
  "0xf39e4b21c84e737df08e2c3b32541d856f508e48": {
    "id": "yooldo-games",
    "circulating_supply": 151800000.0
  },
  "0xd39ba5680e5a59ed032054485a0a8d2d5a6a2366": {
    "id": "mcoin-2",
    "circulating_supply": 1000000000.0
  },
  "0x9025daa1fe2d27700187e0eac670818945f94c2e": {
    "id": "stage",
    "circulating_supply": 0.0
  },
  "0xc6ec7898b0bdf5ac41fbabdbe19250ca4917c5a6": {
    "id": "felis",
    "circulating_supply": 311115924054.60315
  },
  "0xa026ad2ceda16ca5fc28fd3c72f99e2c332c8a26": {
    "id": "xcad-network",
    "circulating_supply": 84769870.55874372
  },
  "0x1cc1aca0dae2d6c4a0e8ae7b4f2d01eabbc435ee": {
    "id": "stronghands-finance",
    "circulating_supply": 14511414.848344488
  },
  "0xe283d0e3b8c102badf5e8166b73e02d96d92f688": {
    "id": "elephant-money",
    "circulating_supply": 497458852483995.5
  },
  "0x94db03752342bc9b5bbf89e3bf0132494f0cb2b3": {
    "id": "dogai",
    "circulating_supply": 0.0
  },
  "0xe3894cb9e92ca78524fb6a30ff072fa5e533c162": {
    "id": "the-everlasting-parachain",
    "circulating_supply": 0.0
  },
  "0x22fffab2e52c4a1dff83b7db7ef319698d48667f": {
    "id": "bull",
    "circulating_supply": 1000000000.0
  },
  "0xde914ed9f96853ab95df19481bd14f0fd9dc2249": {
    "id": "vulpe-finance",
    "circulating_supply": 0.0
  },
  "0x799a290f9cc4085a0ce5b42b5f2c30193a7a872b": {
    "id": "elderglade",
    "circulating_supply": 135222220.0
  },
  "0xd5d0322b6bab6a762c79f8c81a0b674778e13aed": {
    "id": "binance-peg-firo",
    "circulating_supply": 0.0
  },
  "0xa01000c52b234a92563ba61e5649b7c76e1ba0f3": {
    "id": "rocki",
    "circulating_supply": 7885722.52
  },
  "0x4341bb2200176f89eb90eac4fd6cfe958e206005": {
    "id": "eafin",
    "circulating_supply": 218033988.0
  },
  "0x22830be0954ff3bf7929405c488b1bba54a7e0d3": {
    "id": "brcstarter",
    "circulating_supply": 0.0
  },
  "0xff7d6a96ae471bbcd7713af9cb1feeb16cf56b41": {
    "id": "bedrock-token",
    "circulating_supply": 220000000.0
  },
  "0x6d57f5c286e04850c2c085350f2e60aaa7b7c15b": {
    "id": "grok-girl",
    "circulating_supply": 0.0
  },
  "0x5f39dd1bb6db20f3e792c4489f514794cac6392c": {
    "id": "playnity",
    "circulating_supply": 96677552.0
  },
  "0xaa076b62efc6f357882e07665157a271ab46a063": {
    "id": "pleasure-coin",
    "circulating_supply": 63956964574.21926
  },
  "0x0ee7292bd28f4a490f849fb30c28cabab9440f9e": {
    "id": "gemlink",
    "circulating_supply": 107778940.0
  },
  "0x2d060ef4d6bf7f9e5edde373ab735513c0e4f944": {
    "id": "solidus-aitech",
    "circulating_supply": 1592496814.0
  },
  "0x6ad0b271f4b3d7651ae9947a18bae29ca20d83eb": {
    "id": "nft-workx",
    "circulating_supply": 83308917.21289712
  },
  "0xa677bc9bdb10329e488a4d8387ed7a08b2fc9005": {
    "id": "magic-power",
    "circulating_supply": 0.0
  },
  "0x2167afa1c658dc5c4ec975f4af608ff075a8b8ae": {
    "id": "evai-2",
    "circulating_supply": 0.0
  },
  "0x7db13e8b9eaa42fc948268b954dd4e6218cc4cb1": {
    "id": "fight-win-ai",
    "circulating_supply": 0.0
  },
  "0xacf34edcc424128cccc730bf85cdaceebcb3eece": {
    "id": "voice-street",
    "circulating_supply": 0.0
  },
  "0x44f161ae29361e332dea039dfa2f404e0bc5b5cc": {
    "id": "humanity",
    "circulating_supply": 1825000000.0
  },
  "0x8cd0d76c0ad377378ab6ce878a7be686223497ee": {
    "id": "hydraverse",
    "circulating_supply": 0.0
  },
  "0xb626213cb1d52caa1ed71e2a0e62c0113ed8d642": {
    "id": "hughug-coin",
    "circulating_supply": 0.0
  },
  "0x00f71afe867b2dbd2ad4ba14fd139bc6bc659ccd": {
    "id": "xoxo-monkey",
    "circulating_supply": 234371558.67183837
  },
  "0xd16cb89f621820bc19dae1c29c9db6d22813b01d": {
    "id": "coinbidex",
    "circulating_supply": 0.0
  },
  "0xe6884e29ffe5c6f68f4958cf201b0e308f982ac9": {
    "id": "vegasino",
    "circulating_supply": 0.0
  },
  "0x7b665b2f633d9363b89a98b094b1f9e732bd8f86": {
    "id": "amazy",
    "circulating_supply": 0.0
  },
  "0xdd325c38b12903b727d16961e61333f4871a70e0": {
    "id": "elephant-money-trunk",
    "circulating_supply": 121691098.32236499
  },
  "0x679d2c23497d4431311ac001618cd0b8789ac29c": {
    "id": "linkfi",
    "circulating_supply": 0.0
  },
  "0x6587eff07d9ae00f05fae2a3a032b2c1a1dfce41": {
    "id": "freedogs",
    "circulating_supply": 0.0
  },
  "0x3aa6b9a5306d1cd48b0466cfb130b08a70257e12": {
    "id": "gorilla-finance",
    "circulating_supply": 0.0
  },
  "0xfdc66a08b0d0dc44c17bbd471b88f49f50cdd20f": {
    "id": "smardex",
    "circulating_supply": 9264747739.024689
  },
  "0x374c5fb7979d5fdbaad2d95409e235e5cbdfd43c": {
    "id": "milk-alliance",
    "circulating_supply": 493615159.0
  },
  "0xbd4c4dc19f208cda6caacadadc0bff4cd975fa34": {
    "id": "dogs-rock",
    "circulating_supply": 0.0
  },
  "0x68de53b47be0dc566bf4673c748d58bbbad3deb1": {
    "id": "dogegrow",
    "circulating_supply": 0.0
  },
  "0x64cf1e2cab86694ac8b31653460faa47a68f59f0": {
    "id": "gamescoin",
    "circulating_supply": 0.0
  },
  "0xed00fc7d48b57b81fe65d1ce71c0985e4cf442cb": {
    "id": "chirpley",
    "circulating_supply": 742347508.171064
  },
  "0xeb2b7d5691878627eff20492ca7c9a71228d931d": {
    "id": "crepe-2",
    "circulating_supply": 690000000000.0
  },
  "0xee81ca267b8357ba30049d679027ebf65fcf7458": {
    "id": "vopo",
    "circulating_supply": 0.0
  },
  "0x824a50df33ac1b41afc52f4194e2e8356c17c3ac": {
    "id": "kick",
    "circulating_supply": 121342748.7052923
  },
  "0x1861c9058577c3b48e73d91d6f25c18b17fbffe0": {
    "id": "stacktical",
    "circulating_supply": 5566263561.663993
  },
  "0x84c97300a190676a19d1e13115629a11f8482bd1": {
    "id": "dot-dot-finance",
    "circulating_supply": 238878824.52948087
  },
  "0x945cd29a40629ada610c2f6eba3f393756aa4444": {
    "id": "usd1doge",
    "circulating_supply": 0.0
  },
  "0x238950013fa29a3575eb7a3d99c00304047a77b5": {
    "id": "beeper-coin",
    "circulating_supply": 10000000000.0
  },
  "0x97b17ac9a0c4bf03cf3b9ed2ee6e397fb319705b": {
    "id": "bnbull",
    "circulating_supply": 1000000000.0
  },
  "0x5f113f7ef20ff111fd130e83d8e97fd1e0e2518f": {
    "id": "aimalls",
    "circulating_supply": 496875.1226545689
  },
  "0x28ce223853d123b52c74439b10b43366d73fd3b5": {
    "id": "fame-mma",
    "circulating_supply": 6502887433.454422
  },
  "0xf3e07812ebc8604fddb0aa35ff79a03f48f48948": {
    "id": "journart",
    "circulating_supply": 0.0
  },
  "0x22b4fa9a13a0d303ad258ee6d62a6ac60364b0c9": {
    "id": "big-pump",
    "circulating_supply": 0.0
  },
  "0x3cb20d96e866d128bc469a6e66505d46d7f9baba": {
    "id": "bib",
    "circulating_supply": 0.0
  },
  "0x43b35e89d15b91162dea1c51133c4c93bdd1c4af": {
    "id": "sakai-vault",
    "circulating_supply": 3593687.1606989424
  },
  "0x0688977ae5b10075f46519063fd2f03adc052c1f": {
    "id": "5th-scape",
    "circulating_supply": 0.0
  },
  "0x84fd7cc4cd689fc021ee3d00759b6d255269d538": {
    "id": "pankuku",
    "circulating_supply": 0.0
  },
  "0x88691f292b76bf4d2caa5678a54515fae77c33af": {
    "id": "xpense-2",
    "circulating_supply": 20829074.683957618
  },
  "0xbc33b4d48f76d17a1800afcb730e8a6aaada7fe5": {
    "id": "voucher-dot",
    "circulating_supply": 0.0
  },
  "0x18c4af61dbe6fd55d6470943b4ab8530777d009c": {
    "id": "agatech",
    "circulating_supply": 0.0
  },
  "0xedd52d44de950ccc3b2e6abdf0da8e99bb0ec480": {
    "id": "crazy-tiger",
    "circulating_supply": 0.0
  },
  "0x4f7ea8f6487a7007ca054f35c4a7b961f5b18961": {
    "id": "goldencat",
    "circulating_supply": 690689999999.9999
  },
  "0x330f4fe5ef44b4d0742fe8bed8ca5e29359870df": {
    "id": "jade-currency",
    "circulating_supply": 58572217.337
  },
  "0xaf41054c1487b0e5e2b9250c0332ecbce6ce9d71": {
    "id": "ellipsis-x",
    "circulating_supply": 0.0
  },
  "0x7c3b00cb3b40cc77d88329a58574e29cfa3cb9e2": {
    "id": "mintstakeshare",
    "circulating_supply": 0.0
  },
  "0xe6ffa2e574a8bbeb5243d2109b6b11d4a459f88b": {
    "id": "hippo-token",
    "circulating_supply": 0.0
  },
  "0x193397bb76868c6873e733ad60d5953843ebc84e": {
    "id": "memetoon",
    "circulating_supply": 0.0
  },
  "0xfb62ae373aca027177d1c18ee0862817f9080d08": {
    "id": "my-defi-pet",
    "circulating_supply": 50230000.0
  },
  "0xfb6115445bff7b52feb98650c87f44907e58f802": {
    "id": "aave",
    "circulating_supply": 15227279.117489727
  },
  "0xfb5b838b6cfeedc2873ab27866079ac55363d37e": {
    "id": "floki",
    "circulating_supply": 9660258458122.0
  },
  "0xfebe8c1ed424dbf688551d4e2267e7a53698f0aa": {
    "id": "vita-inu",
    "circulating_supply": 899596453417793.4
  },
  "0xfd5840cd36d94d7229439859c0112a4185bc0255": {
    "id": "venus-usdt",
    "circulating_supply": 0.0
  },
  "0xfce146bf3146100cfe5db4129cf6c82b0ef4ad8c": {
    "id": "renbtc",
    "circulating_supply": 304.49818869
  },
  "0xf9cec8d50f6c8ad3fb6dccec577e05aa32b224fe": {
    "id": "chromaway",
    "circulating_supply": 846581914.378197
  },  "0xf859bf77cbe8699013d6dbc7c2b926aaf307f830": {
    "id": "berry-data",
    "circulating_supply": 6412985.022030054
  },
  "0xf7686f43591302cd9b4b9c4fe1291473fae7d9c9": {
    "id": "lossless",
    "circulating_supply": 76075369.34
  },
  "0xf508fcd89b8bd15579dc79a6827cb4686a3592c8": {
    "id": "venus-eth",
    "circulating_supply": 0.0
  },
  "0xf307910a4c7bbc79691fd374889b36d8531b08e3": {
    "id": "ankr",
    "circulating_supply": 10000000000.0
  },
  "0xf16e81dce15b08f326220742020379b855b87df9": {
    "id": "ice-token",
    "circulating_supply": 6748850.016657832
  },
  "0xeca88125a5adbe82614ffc12d0db554e2e2867c8": {
    "id": "venus-usdc",
    "circulating_supply": 0.0
  },
  "0xebaffc2d2ea7c66fb848c48124b753f93a0a90ec": {
    "id": "asia-coin",
    "circulating_supply": 50000000.0
  },
  "0xea89199344a492853502a7a699cc4230854451b8": {
    "id": "oni-token",
    "circulating_supply": 39453015.13579266
  },
  "0xeeeeeb57642040be42185f49c52f7e9b38f8eeee": {
    "id": "elk-finance",
    "circulating_supply": 16134216.0
  },
  "0xed28a457a5a76596ac48d87c0f577020f6ea1c4c": {
    "id": "ptokens-btc",
    "circulating_supply": 8.002964314097083
  },
  "0xeceb87cf00dcbf2d4e2880223743ff087a995ad9": {
    "id": "numbers-protocol",
    "circulating_supply": 829632333.0
  },
  "0xeb953eda0dc65e3246f43dc8fa13f35623bdd5ed": {
    "id": "rainicorn",
    "circulating_supply": 486362378.0
  },
  "0xe9e7cea3dedca5984780bafc599bd69add087d56": {
    "id": "binance-peg-busd",
    "circulating_supply": 312477997.5095268
  },
  "0xe91a8d2c584ca93c7405f15c22cdfe53c29896e3": {
    "id": "dextools",
    "circulating_supply": 70651082.40209083
  },
  "0xe90d1567ecef9282cc1ab348d9e9e2ac95659b99": {
    "id": "coinxpad",
    "circulating_supply": 0.0
  },
  "0xe87e15b9c7d989474cb6d8c56b3db4efad5b21e8": {
    "id": "hokkaidu-inu",
    "circulating_supply": 2869101054.44952
  },
  "0xe80772eaf6e2e18b651f160bc9158b2a5cafca65": {
    "id": "usd",
    "circulating_supply": 48085096.3705041
  },
  "0xe7c9c6bc87b86f9e5b57072f907ee6460b593924": {
    "id": "tower",
    "circulating_supply": 3868062392.304935
  },
  "0xe6df05ce8c8301223373cf5b969afcb1498c5528": {
    "id": "bnb48-club-token",
    "circulating_supply": 3379999.04
  },
  "0xe60eaf5a997dfae83739e035b005a33afdcc6df5": {
    "id": "deri-protocol",
    "circulating_supply": 131192006.30776003
  },
  "0xe2a59d5e33c6540e18aaa46bf98917ac3158db0d": {
    "id": "purefi",
    "circulating_supply": 93466552.8636034
  },
  "0xe2604c9561d490624aa35e156e65e590eb749519": {
    "id": "goldminer",
    "circulating_supply": 0.0
  },
  "0xe20b9e246db5a0d21bf9209e4858bc9a3ff7a034": {
    "id": "wrapped-banano",
    "circulating_supply": 0.0
  },
  "0xe0f94ac5462997d2bc57287ac3a3ae4c31345d66": {
    "id": "ceek",
    "circulating_supply": 983000882.0
  },
  "0xe0191fefdd0d2b39b1a2e4e029ccda8a481b7995": {
    "id": "cryptomines-reborn",
    "circulating_supply": 0.0
  },
  "0xde3dbbe30cfa9f437b293294d1fd64b26045c71a": {
    "id": "nftb",
    "circulating_supply": 706214577.1558244
  },
  "0xdaacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92": {
    "id": "pnetwork",
    "circulating_supply": 87920342.4145748
  },
  "0xdf9e1a85db4f985d5bb5644ad07d9d7ee5673b5e": {
    "id": "mm72",
    "circulating_supply": 69999998803.15154
  },
  "0xd9780513292477c4039dfda1cfcd89ff111e9da5": {
    "id": "tegro",
    "circulating_supply": 0.0
  },
  "0xd9025e25bb6cf39f8c926a704039d2dd51088063": {
    "id": "coinary-token",
    "circulating_supply": 213547586.7512549
  },
  "0xd88ca08d8eec1e9e09562213ae83a7853ebb5d28": {
    "id": "xwin-finance",
    "circulating_supply": 14319924.34840307
  },
  "0xd73f32833b6d5d9c8070c23e599e283a3039823c": {
    "id": "waterfall-governance-token",
    "circulating_supply": 62704327.0
  },
  "0xd6fdde76b8c1c45b33790cc8751d5b88984c44ec": {
    "id": "strikecoin",
    "circulating_supply": 847976290.02959
  },
  "0xd632bd021a07af70592ce1e18717ab9aa126decb": {
    "id": "kangal",
    "circulating_supply": 100000000000.0
  },
  "0xd4fbc57b6233f268e7fba3b66e62719d74deecbc": {
    "id": "modefi",
    "circulating_supply": 16076764.49902935
  },
  "0xd32d01a43c869edcd1117c640fbdcfcfd97d9d65": {
    "id": "nominex",
    "circulating_supply": 224160636.779705
  },
  "0xd21d29b38374528675c34936bf7d5dd693d2a577": {
    "id": "parsiq",
    "circulating_supply": 292756872.0
  },
  "0xcfcecfe2bd2fed07a9145222e8a7ad9cf1ccd22a": {
    "id": "adshares",
    "circulating_supply": 38733597.547125
  },
  "0xcaf5191fc480f43e4df80106c7695eca56e48b18": {
    "id": "deapcoin",
    "circulating_supply": 27526332268.328953
  },
  "0xca830317146bfdde71e7c0b880e2ec1f66e273ee": {
    "id": "polygod",
    "circulating_supply": 0.0
  },
  "0xcf6bb5389c92bdda8a3747ddb454cb7a64626c63": {
    "id": "venus",
    "circulating_supply": 16740663.914255643
  },
  "0xc9457161320210d22f0d0d5fc1309acb383d4609": {
    "id": "dovu",
    "circulating_supply": 308817122.2947917
  },
  "0xc864019047b864b6ab609a968ae2725dfaee808a": {
    "id": "biconomy-exchange-token",
    "circulating_supply": 282124331508.77277
  },
  "0xc7981767f644c7f8e483dabdc413e8a371b83079": {
    "id": "liquidus",
    "circulating_supply": 6559079.517146707
  },
  "0xc748673057861a797275cd8a068abb95a902e8de": {
    "id": "baby-doge-coin",
    "circulating_supply": 1.7035248306988077e+17
  },
  "0xc7091aa18598b87588e37501b6ce865263cd67ce": {
    "id": "cheesecakeswap",
    "circulating_supply": 0.0
  },
  "0xc6dddb5bc6e61e0841c54f3e723ae1f3a807260b": {
    "id": "urus-token",
    "circulating_supply": 484659.00185326004
  },
  "0xc5e6689c9c8b02be7c49912ef19e79cf24977f03": {
    "id": "alpaca",
    "circulating_supply": 10922261.1246256
  },
  "0xc53708664b99df348dd27c3ac0759d2da9c40462": {
    "id": "gourmetgalaxy",
    "circulating_supply": 3322141.4784610313
  },
  "0xc2e9d07f66a89c44062459a47a0d2dc038e4fb16": {
    "id": "pstake-staked-bnb",
    "circulating_supply": 0.0
  },
  "0xba2ae424d960c26247dd6c32edc70b295c744c43": {
    "id": "binance-peg-dogecoin",
    "circulating_supply": 2564404182.613781
  },
  "0xb86abcb37c3a4b64f74f59301aff131a1becc787": {
    "id": "zilliqa",
    "circulating_supply": 18763171821.666676
  },
  "0xb6c53431608e626ac81a9776ac3e999c5556717c": {
    "id": "wrapped-telos",
    "circulating_supply": 0.0
  },
  "0xb5be8d87fce6ce87a24b90abdb019458a8ec31f9": {
    "id": "obortech",
    "circulating_supply": 197500000.0
  },
  "0xb59490ab09a0f526cc7305822ac65f2ab12f9723": {
    "id": "litentry",
    "circulating_supply": 45166534.0
  },
  "0xb465f3cb6aba6ee375e12918387de1eac2301b05": {
    "id": "trivian",
    "circulating_supply": 615003826.53
  },
  "0xb3a6381070b1a15169dea646166ec0699fdaea79": {
    "id": "cyberdragon-gold",
    "circulating_supply": 0.0
  },
  "0xb2ea51baa12c461327d12a2069d47b30e680b69d": {
    "id": "space-misfits",
    "circulating_supply": 0.0
  },
  "0xaf6162dc717cfc8818efc8d6f46a41cf7042fcba": {
    "id": "atlas-usv",
    "circulating_supply": 105483.358498926
  },
  "0xaef0d72a118ce24fee3cd1d43d383897d05b4e99": {
    "id": "winklink-bsc",
    "circulating_supply": 0.0
  },
  "0xacb2d47827c9813ae26de80965845d80935afd0b": {
    "id": "macaronswap",
    "circulating_supply": 824457.655364381
  },
  "0xaf53d56ff99f1322515e54fdde93ff8b3b7dafd5": {
    "id": "prometeus",
    "circulating_supply": 18250000.0
  },
  "0xaec945e04baf28b135fa7c640f624f8d90f1c3a6": {
    "id": "coin98",
    "circulating_supply": 999999716.0
  },
  "0xace3574b8b054e074473a9bd002e5dc6dd3dff1b": {
    "id": "rbx-token",
    "circulating_supply": 0.0
  },
  "0xac472d0eed2b8a2f57a6e304ea7ebd8e88d1d36f": {
    "id": "anime-token",
    "circulating_supply": 60724419.8695
  },
  "0xa9c41a46a6b3531d28d5c32f6633dd2ff05dfb90": {
    "id": "waultswap",
    "circulating_supply": 7518356517.5973
  },
  "0xa2b726b1145a4773f68593cf171187d8ebe4d495": {
    "id": "injective-protocol",
    "circulating_supply": 97727220.33
  },
  "0xa1faa113cbe53436df28ff0aee54275c13b40975": {
    "id": "alpha-finance",
    "circulating_supply": 948000000.0
  },
  "0xa184088a740c695e156f91f5cc086a06bb78b827": {
    "id": "auto",
    "circulating_supply": 0.0
  },
  "0xa045e37a0d1dd3a45fefb8803d22457abc0a728a": {
    "id": "grizzly-honey",
    "circulating_supply": 1479704.601155371
  },
  "0xffba7529ac181c2ee1844548e6d7061c9a597df4": {
    "id": "coin-capsule",
    "circulating_supply": 1829471951.0000002
  },
  "0xfd7b3a77848f1c2d67e05e54d78d174a0c850335": {
    "id": "binance-peg-ontology",
    "circulating_supply": 0.0
  },
  "0xfa40d8fc324bcdd6bbae0e086de886c571c225d4": {
    "id": "wizardia",
    "circulating_supply": 105126240.94333333
  },
  "0xfa262f303aa244f9cc66f312f0755d89c3793192": {
    "id": "rigel-protocol",
    "circulating_supply": 900000.0
  },
  "0xf952fc3ca7325cc27d15885d37117676d25bfda6": {
    "id": "goose-finance",
    "circulating_supply": 41186886.64538041
  },
  "0xf8a0bf9cf54bb92f17374d9e9a321e6a111a51bd": {
    "id": "chainlink",
    "circulating_supply": 678099970.4527868
  },
  "0xf7b6d7e3434cb9441982f9534e6998c43eef144a": {
    "id": "asva",
    "circulating_supply": 0.0
  },
  "0xf78d2e7936f5fe18308a3b2951a93b6c4a41f5e2": {
    "id": "mantra-dao",
    "circulating_supply": 1061979142.294719
  },
  "0xf7844cb890f4c339c497aeab599abdc3c874b67a": {
    "id": "nft-art-finance",
    "circulating_supply": 2.4930005585016504e+16
  },
  "0xf606bd19b1e61574ed625d9ea96c841d4e247a32": {
    "id": "guardian-token",
    "circulating_supply": 0.0
  },
  "0xf5d8a096cccb31b9d7bce5afe812be23e3d4690d": {
    "id": "happyfans",
    "circulating_supply": 28561930447.3892
  },
  "0xf4ed363144981d3a65f42e7d0dc54ff9eef559a1": {
    "id": "faraland",
    "circulating_supply": 42600000.0
  },
  "0xf218184af829cf2b0019f8e6f0b2423498a36983": {
    "id": "math",
    "circulating_supply": 185020543.24
  },
  "0xf21768ccbc73ea5b6fd3c687208a7c2def2d966e": {
    "id": "reef",
    "circulating_supply": 43896804623.23893
  },
  "0xf0dcf7ac48f8c745f2920d03dff83f879b80d438": {
    "id": "gami",
    "circulating_supply": 0.0
  },
  "0xee9801669c6138e84bd50deb500827b776777d28": {
    "id": "o3-swap",
    "circulating_supply": 35725691.640542015
  },
  "0xed8c8aa8299c10f067496bb66f8cc7fb338a3405": {
    "id": "prosper",
    "circulating_supply": 51394815.0
  },
  "0xeca41281c24451168a37211f0bc2b8645af45092": {
    "id": "token-pocket",
    "circulating_supply": 3466457399.0
  },
  "0xe9c803f48dffe50180bd5b01dc04da939e3445fc": {
    "id": "velas",
    "circulating_supply": 2751422972.094905
  },
  "0xe8176d414560cfe1bf82fd73b986823b89e4f545": {
    "id": "step-hero",
    "circulating_supply": 0.0
  },
  "0xe5ba47fd94cb645ba4119222e34fb33f59c7cd90": {
    "id": "safuu",
    "circulating_supply": 0.0
  },
  "0xe4fae3faa8300810c835970b9187c268f55d998f": {
    "id": "catecoin",
    "circulating_supply": 57700161212436.68
  },
  "0xe336a772532650bc82828e9620dd0d5a3b78bfe8": {
    "id": "digimetaverse",
    "circulating_supply": 0.0
  },
  "0xe0e514c71282b6f4e823703a39374cf58dc3ea4f": {
    "id": "belt",
    "circulating_supply": 20170898.310170945
  },
  "0xe02df9e3e622debdd69fb838bb799e3f168902c5": {
    "id": "bakerytoken",
    "circulating_supply": 288705144.0
  },
  "0xddc0dbd7dc799ae53a98a60b54999cb6ebb3abf0": {
    "id": "safeblast",
    "circulating_supply": 0.0
  },
  "0xdb021b1b247fe2f1fa57e0a87c748cc1e321f07f": {
    "id": "ampleforth",
    "circulating_supply": 19939153.203285523
  },
  "0xdae6c2a48bfaa66b43815c5548b10800919c993e": {
    "id": "kattana",
    "circulating_supply": 2481904.636763707
  },
  "0xd9c2d319cd7e6177336b0a9c93c21cb48d84fb54": {
    "id": "hapi",
    "circulating_supply": 732248.4234118699
  },
  "0xd98560689c6e748dc37bc410b4d3096b1aa3d8c2": {
    "id": "defi-for-you",
    "circulating_supply": 601416467.712
  },  "0xd8047afecb86e44eff3add991b9f063ed4ca716b": {
    "id": "good-games-guild",
    "circulating_supply": 40000000.0
  },
  "0xd7730681b1dc8f6f969166b29d8a5ea8568616a3": {
    "id": "nafter",
    "circulating_supply": 441199428.9214712
  },
  "0xd74b782e05aa25c50e7330af541d46e18f36661c": {
    "id": "richquack",
    "circulating_supply": 4.435454309473764e+16
  },
  "0xd48474e7444727bf500a32d5abe01943f3a59a64": {
    "id": "bitbook-token",
    "circulating_supply": 0.0
  },
  "0xd44fd09d74cd13838f137b590497595d6b3feea4": {
    "id": "cryptomines-eternal",
    "circulating_supply": 0.0
  },
  "0xd41fdb03ba84762dd66a0af1a6c8540ff1ba5dfb": {
    "id": "safepal",
    "circulating_supply": 500000000.0
  },
  "0xd40bedb44c081d2935eeba6ef5a3c8a31a1bbe13": {
    "id": "metahero",
    "circulating_supply": 9366213223.195871
  },
  "0xd3c325848d7c6e29b574cb0789998b2ff901f17e": {
    "id": "1art",
    "circulating_supply": 314863767.9503962
  },
  "0xc9849e6fdb743d08faee3e34dd2d1bc69ea11a51": {
    "id": "pancake-bunny",
    "circulating_supply": 510232.0791391204
  },
  "0xc5326b32e8baef125acd68f8bc646fd646104f1c": {
    "id": "zap",
    "circulating_supply": 460000000.0
  },
  "0xc3028fbc1742a16a5d69de1b334cbce28f5d7eb3": {
    "id": "starsharks",
    "circulating_supply": 0.0
  },
  "0xc13b7a43223bb9bf4b69bd68ab20ca1b79d81c75": {
    "id": "juggernaut",
    "circulating_supply": 100210415.86298622
  },
  "0xc1165227519ffd22fdc77ceb1037b9b284eef068": {
    "id": "bnsd-finance",
    "circulating_supply": 187089107.57722083
  },
  "0xc0eff7749b125444953ef89682201fb8c6a917cd": {
    "id": "horizon-protocol",
    "circulating_supply": 184339806.1574587
  },
  "0xc0ecb8499d8da2771abcbf4091db7f65158f1468": {
    "id": "switcheo",
    "circulating_supply": 1720665159.8054342
  },
  "0xbf5140a22578168fd562dccf235e5d43a02ce9b1": {
    "id": "uniswap",
    "circulating_supply": 600483073.71
  },
  "0xbe1a001fe942f96eea22ba08783140b9dcc09d28": {
    "id": "beta-finance",
    "circulating_supply": 950000000.0
  },
  "0xbd2949f67dcdc549c6ebe98696449fa79d988a9f": {
    "id": "meter",
    "circulating_supply": 32276310.0
  },
  "0xbc7d6b50616989655afd682fb42743507003056d": {
    "id": "alchemy-pay",
    "circulating_supply": 4943691067.145604
  },
  "0xbb46693ebbea1ac2070e59b4d043b47e2e095f86": {
    "id": "bfg-token",
    "circulating_supply": 688475450.4725574
  },
  "0xbac1df744df160877cdc45e13d0394c06bc388ff": {
    "id": "nftmall",
    "circulating_supply": 19982908.33393507
  },
  "0xbf05279f9bf1ce69bbfed670813b7e431142afa4": {
    "id": "million",
    "circulating_supply": 1000000.0
  },
  "0xbc7370641ddcf16a27eea11230af4a9f247b61f9": {
    "id": "xana",
    "circulating_supply": 4925701908.0
  },
  "0xbbca42c60b5290f2c48871a596492f93ff0ddc82": {
    "id": "domi",
    "circulating_supply": 447411649.58
  },
  "0xb5102cee1528ce2c760893034a4603663495fd72": {
    "id": "token-dforce-usd",
    "circulating_supply": 15453332.51134857
  },
  "0xb44c63a09adf51f5e62cc7b63628b1b789941fa0": {
    "id": "reflex",
    "circulating_supply": 0.0
  },
  "0xb2bd0749dbe21f623d9baba856d3b0f0e1bfec9c": {
    "id": "dusk-network",
    "circulating_supply": 500000000.0
  },
  "0xb248a295732e0225acd3337607cc01068e3b9c10": {
    "id": "venus-xrp",
    "circulating_supply": 0.0
  },
  "0xb149b030cfa47880af0bde4cd36539e4c928b3eb": {
    "id": "nutgain",
    "circulating_supply": 0.0
  },
  "0xb0e1fc65c1a741b4662b813eb787d369b8614af1": {
    "id": "impossible-finance",
    "circulating_supply": 10086744.94743067
  },
  "0xb0d502e938ed5f4df2e681fe6e419ff29631d62b": {
    "id": "stargate-finance",
    "circulating_supply": 971464728.370142
  },
  "0xb0b195aefa3650a6908f15cdac7d92f8a5791b0b": {
    "id": "bob",
    "circulating_supply": 341507.1906610738
  },
  "0xae9269f27437f0fcbc232d39ec814844a51d6b8f": {
    "id": "burger-swap",
    "circulating_supply": 0.0
  },
  "0xae2df9f730c54400934c06a17462c41c08a06ed8": {
    "id": "dogebonk",
    "circulating_supply": 543745067193654.0
  },
  "0xad6742a35fb341a9cc6ad674738dd8da98b94fb1": {
    "id": "wombat-exchange",
    "circulating_supply": 292261877.0561284
  },
  "0xad29abb318791d579433d831ed122afeaf29dcfe": {
    "id": "wrapped-fantom",
    "circulating_supply": 0.0
  },
  "0xacb8f52dc63bb752a51186d1c55868adbffee9c1": {
    "id": "bunnypark",
    "circulating_supply": 0.0
  },
  "0xac51066d7bec65dc4589368da368b212745d63e8": {
    "id": "my-neighbor-alice",
    "circulating_supply": 92083333.0
  },
  "0xa58950f05fea2277d2608748412bf9f802ea4901": {
    "id": "wall-street-games",
    "circulating_supply": 425305470924668.25
  },
  "0xa57ac35ce91ee92caefaa8dc04140c8e232c2e50": {
    "id": "pitbull",
    "circulating_supply": 3.8849398752619096e+16
  },
  "0xa4b6573c9ae09d81e4d1360e6402b81f52557098": {
    "id": "coreto",
    "circulating_supply": 412127287.4926551
  },
  "0xa2120b9e674d3fc3875f415a7df52e382f141225": {
    "id": "automata",
    "circulating_supply": 587792028.2579365
  },
  "0x9fd87aefe02441b123c3c32466cd9db4c578618f": {
    "id": "thetan-arena",
    "circulating_supply": 0.0
  },
  "0x9f589e3eabe42ebc94a44727b3f3531c0c877809": {
    "id": "tokocrypto",
    "circulating_supply": 75000000.0
  },
  "0x9c67638c4fa06fd47fb8900fc7f932f7eab589de": {
    "id": "arker-2",
    "circulating_supply": 0.0
  },
  "0x9fb9a33956351cf4fa040f65a13b835a3c8764e3": {
    "id": "multichain-bsc",
    "circulating_supply": 0.0
  },
  "0x9d173e6c594f479b4d47001f8e6a95a7adda42bc": {
    "id": "cryptozoon",
    "circulating_supply": 816637619.9463553
  },
  "0x9c65ab58d8d978db963e63f2bfb7121627e3a739": {
    "id": "mdex-bsc",
    "circulating_supply": 0.0
  },
  "0x9ba6a67a6f3b21705a46b380a1b97373a33da311": {
    "id": "fear",
    "circulating_supply": 26253768.76374718
  },
  "0x9ab70e92319f0b9127df78868fd3655fb9f1e322": {
    "id": "weway",
    "circulating_supply": 6643232564.981873
  },
  "0x99c6e435ec259a7e8d65e1955c9423db624ba54c": {
    "id": "finminity",
    "circulating_supply": 3337761.0655555557
  },
  "0x9678e42cebeb63f23197d726b29b1cb20d0064e5": {
    "id": "binance-peg-iotex",
    "circulating_supply": 0.0
  },
  "0x965b0df5bda0e7a0649324d78f03d5f7f2de086a": {
    "id": "cook",
    "circulating_supply": 1973233859.219826
  },
  "0x965f527d9159dce6288a2219db51fc6eef120dd1": {
    "id": "biswap",
    "circulating_supply": 498978200.0
  },
  "0x9617857e191354dbea0b714d78bc59e57c411087": {
    "id": "lympo-market-token",
    "circulating_supply": 155250012.0
  },
  "0x95c78222b3d6e262426483d42cfa53685a67ab9d": {
    "id": "venus-busd",
    "circulating_supply": 0.0
  },
  "0x95a1199eba84ac5f19546519e287d43d2f0e1b41": {
    "id": "rabbit-finance",
    "circulating_supply": 106449488.172247
  },
  "0x95ee03e1e2c5c4877f9a298f1c0d6c98698fab7b": {
    "id": "duet-protocol",
    "circulating_supply": 0.0
  },
  "0x9573c88ae3e37508f87649f87c4dd5373c9f31e0": {
    "id": "monsta-infinite",
    "circulating_supply": 36870683.49184209
  },
  "0x9528cceb678b90daf02ca5ca45622d5cbaf58a30": {
    "id": "gocryptome",
    "circulating_supply": 0.0
  },
  "0x94b69263fca20119ae817b6f783fc0f13b02ad50": {
    "id": "league-of-ancients",
    "circulating_supply": 423615908.3026826
  },
  "0x949d48eca67b17269629c7194f4b727d4ef9e5d6": {
    "id": "merit-circle",
    "circulating_supply": 11906525.34137866
  },
  "0x948d2a81086a075b3130bac19e4c6dee1d2e3fe8": {
    "id": "helmet-insure",
    "circulating_supply": 42464928.919309124
  },
  "0x947950bcc74888a40ffa2593c5798f11fc9124c4": {
    "id": "sushi",
    "circulating_supply": 192789255.8554817
  },
  "0x936b6659ad0c1b244ba8efe639092acae30dc8d6": {
    "id": "corite",
    "circulating_supply": 219371322.0
  },
  "0x4c882ec256823ee773b25b414d36f92ef58a7c0c": {
    "id": "pstake-finance",
    "circulating_supply": 500000000.0
  },
  "0x4c769928971548eb71a3392eaf66bedc8bef4b80": {
    "id": "harrypotterobamasonic10inu",
    "circulating_supply": 0.0
  },
  "0x4bd17003473389a42daf6a0a729f6fdb328bbbd7": {
    "id": "vai",
    "circulating_supply": 2968889.650676287
  },
  "0x4ba0057f784858a48fe351445c672ff2a3d43515": {
    "id": "kalmar",
    "circulating_supply": 8542030.099041097
  },
  "0x489580eb70a50515296ef31e8179ff3e77e24965": {
    "id": "dappradar",
    "circulating_supply": 1525808338.019161
  },
  "0x482e6bd0a178f985818c5dfb9ac77918e8412fba": {
    "id": "colizeum",
    "circulating_supply": 0.0
  },
  "0x4803ac6b79f9582f69c4fa23c72cb76dd1e46d8d": {
    "id": "topmanager",
    "circulating_supply": 0.0
  },
  "0x47bead2563dcbf3bf2c9407fea4dc236faba485a": {
    "id": "swipe",
    "circulating_supply": 655170869.9034001
  },
  "0x477bc8d23c634c154061869478bce96be6045d12": {
    "id": "seedify-fund",
    "circulating_supply": 63562839.95
  },
  "0x475bfaa1848591ae0e6ab69600f48d828f61a80e": {
    "id": "everdome",
    "circulating_supply": 91138701659.0
  },
  "0x474021845c4643113458ea4414bdb7fb74a01a77": {
    "id": "uno-re",
    "circulating_supply": 133468650.0
  },
  "0x46d502fac9aea7c5bc7b13c8ec9d02378c33d36f": {
    "id": "wolfsafepoorpeople",
    "circulating_supply": 1.3542390331799896e+16
  },
  "0x4691937a7508860f876c9c0a2a617e7d9e945d4b": {
    "id": "woo-network",
    "circulating_supply": 1905073607.037396
  },
  "0x44ec807ce2f4a6f2737a92e985f318d035883e47": {
    "id": "hashflow",
    "circulating_supply": 601900287.0166
  },
  "0x44754455564474a89358b2c2265883df993b12f0": {
    "id": "zeroswap",
    "circulating_supply": 74269841.0
  },
  "0x43f5b29d63cedc5a7c1724dbb1d698fde05ada21": {
    "id": "fodl-finance",
    "circulating_supply": 378646641.67698294
  },
  "0x4374f26f0148a6331905edf4cd33b89d8eed78d1": {
    "id": "yoshi-exchange",
    "circulating_supply": 153000000.0
  },
  "0x4338665cbb7b2485a8855a139b75d5e34ab0db94": {
    "id": "binance-peg-litecoin",
    "circulating_supply": 0.0
  },
  "0x42f6f551ae042cbe50c739158b4f0cac0edb9096": {
    "id": "nerve-finance",
    "circulating_supply": 0.0
  },
  "0x426c72701833fddbdfc06c944737c6031645c708": {
    "id": "defina-finance",
    "circulating_supply": 58892469.0
  },
  "0x422e3af98bc1de5a1838be31a56f75db4ad43730": {
    "id": "coinwind",
    "circulating_supply": 0.0
  },
  "0x4197c6ef3879a08cd51e5560da5064b773aa1d29": {
    "id": "acryptos",
    "circulating_supply": 1671358.888463518
  },
  "0x410a56541bd912f9b60943fcb344f1e3d6f09567": {
    "id": "minto",
    "circulating_supply": 6451236.221757991
  },
  "0x41065e3428188ba6eb27fbdde8526ae3af8e3830": {
    "id": "swash",
    "circulating_supply": 994960022.3593615
  },
  "0x40c8225329bd3e28a043b029e0d07a5344d2c27c": {
    "id": "ageofgods",
    "circulating_supply": 0.0
  },
  "0x3c6dad0475d3a1696b359dc04c99fd401be134da": {
    "id": "saito",
    "circulating_supply": 3000000000.0
  },
  "0x3b198e26e473b8fab2085b37978e36c9de5d7f68": {
    "id": "chronobank",
    "circulating_supply": 710112.8108
  },
  "0x3ad9594151886ce8538c1ff615efa2385a8c3a88": {
    "id": "safemars",
    "circulating_supply": 383336206950550.0
  },
  "0x3fcca8648651e5b974dd6d3e50f61567779772a8": {
    "id": "moonpot",
    "circulating_supply": 0.0
  },
  "0x3f56e0c36d275367b8c502090edf38289b3dea0d": {
    "id": "mai-bsc",
    "circulating_supply": 0.0
  },
  "0x3ee2200efb3400fabb9aacf31297cbdd1d435d47": {
    "id": "binance-peg-cardano",
    "circulating_supply": 0.0
  },
  "0x3da932456d082cba208feb0b096d49b202bf89c8": {
    "id": "dego-finance",
    "circulating_supply": 21000000.0
  },
  "0x3c45a24d36ab6fc1925533c1f57bc7e1b6fba8a4": {
    "id": "option-room",
    "circulating_supply": 12493373.14272445
  },
  "0x368ce786ea190f32439074e8d22e12ecb718b44c": {
    "id": "epik-prime",
    "circulating_supply": 1224673076.0
  },
  "0x352cb5e19b12fc216548a2677bd0fce83bae434b": {
    "id": "bittorrent",
    "circulating_supply": 986061142857000.0
  },  "0x347e430b7cd1235e216be58ffa13394e5009e6e2": {
    "id": "gaia-everworld",
    "circulating_supply": 422470685.39357674
  },
  "0x339c72829ab7dd45c3c52f965e7abe358dd8761e": {
    "id": "wanaka-farm",
    "circulating_supply": 173520264.82
  },
  "0x334b3ecb4dca3593bccc3c7ebd1a1c1d1780fbf1": {
    "id": "venus-dai",
    "circulating_supply": 0.0
  },
  "0x32f1518baace69e85b9e5ff844ebd617c52573ac": {
    "id": "dexsport",
    "circulating_supply": 195631763.16432187
  },
  "0x3203c9e46ca618c8c1ce5dc67e7e9d75f5da2377": {
    "id": "mobox",
    "circulating_supply": 500322467.0
  },
  "0x31d0a7ada4d4c131eb612db48861211f63e57610": {
    "id": "bscstarter",
    "circulating_supply": 936914.19
  },
  "0x3192ccddf1cdce4ff055ebc80f3f0231b86a7e30": {
    "id": "insurace",
    "circulating_supply": 68888257.2719627
  },
  "0x31471e0791fcdbe82fbf4c44943255e923f1b794": {
    "id": "plant-vs-undead-token",
    "circulating_supply": 285000000.0
  },
  "0x30807d3b851a31d62415b8bb7af7dca59390434a": {
    "id": "radioshack",
    "circulating_supply": 3438960409.98545
  },
  "0x3019bf2a2ef8040c242c9a4c5c4bd4c81678b2a1": {
    "id": "stepn",
    "circulating_supply": 3108489518.327395
  },
  "0x2ff3d0f6990a40261c66e1ff2017acbc282eb6d0": {
    "id": "venus-sxp",
    "circulating_supply": 0.0
  },
  "0x2ff0b946a6782190c4fe5d4971cfe79f0b6e4df2": {
    "id": "mysterium",
    "circulating_supply": 32433365.0
  },
  "0x2ed9a5c8c13b93955103b9a7c167b67ef4d568a3": {
    "id": "mask-network",
    "circulating_supply": 100000000.0
  },
  "0x2fa5daf6fe0708fbd63b1a7d1592577284f52256": {
    "id": "unmarshal",
    "circulating_supply": 63342378.860617556
  },
  "0x2c717059b366714d267039af8f59125cadce6d8c": {
    "id": "metashooter",
    "circulating_supply": 0.0
  },
  "0x2ab0e9e4ee70fff1fb9d67031e44f6410170d00e": {
    "id": "xen-crypto-bsc",
    "circulating_supply": 0.0
  },
  "0x2a48ece377b87ce941406657b9278b4459595e06": {
    "id": "lunatics",
    "circulating_supply": 0.0
  },
  "0x29a63f4b209c29b4dc47f06ffa896f32667dad2c": {
    "id": "pundi-x-purse",
    "circulating_supply": 27461333560.399906
  },
  "0x2859e4544c4bb03966803b044a93563bd2d0dd4d": {
    "id": "binance-peg-shib",
    "circulating_supply": 0.0
  },
  "0x27ae27110350b98d564b9a3eed31baebc82d878d": {
    "id": "cumrocket",
    "circulating_supply": 1320428309.0
  },
  "0x26d3163b165be95137cee97241e716b2791a7572": {
    "id": "dibs-share",
    "circulating_supply": 0.0
  },
  "0x250632378e573c6be1ac2f97fcdf00515d0aa91b": {
    "id": "binance-eth",
    "circulating_supply": 0.0
  },
  "0x23e8a70534308a4aaf76fb8c32ec13d17a3bd89e": {
    "id": "lusd",
    "circulating_supply": 0.0
  },
  "0x23b8683ff98f9e4781552dfe6f12aa32814924e8": {
    "id": "jarvis-synthetic-euro",
    "circulating_supply": 0.0
  },
  "0x23ce9e926048273ef83be0a3a8ba9cb6d45cd978": {
    "id": "mines-of-dalarnia",
    "circulating_supply": 0.0
  },
  "0x23396cf899ca06c4472205fc903bdb4de249d6fc": {
    "id": "wrapped-ust",
    "circulating_supply": 0.0
  },
  "0x232fb065d9d24c34708eedbf03724f2e95abe768": {
    "id": "sheesha-finance",
    "circulating_supply": 58936.81809
  },
  "0x20de22029ab63cf9a7cf5feb2b737ca1ee4c82a6": {
    "id": "tranchess",
    "circulating_supply": 204732636.0
  },
  "0x1d6cbdc6b29c6afbae65444a1f65ba9252b8ca83": {
    "id": "tor",
    "circulating_supply": 17070481.49032999
  },
  "0x1bdd3cf7f79cfb8edbb955f20ad99211551ba275": {
    "id": "stader-bnbx",
    "circulating_supply": 16407.61792752348
  },
  "0x1ba8d3c4c219b124d351f603060663bd1bcd9bbf": {
    "id": "tornado-cash",
    "circulating_supply": 3810550.883649667
  },
  "0x1a9b49e9f075c37fe5f86c916bac9deb33556d7e": {
    "id": "aspo-world",
    "circulating_supply": 0.0
  },
  "0x1fa4a73a3f0133f0025378af00236f3abdee5d63": {
    "id": "binance-peg-near-protocol",
    "circulating_supply": 0.0
  },
  "0x1ffd0b47127fdd4097e54521c9e2c7f0d66aafc5": {
    "id": "autobahn-network",
    "circulating_supply": 127121646.93647096
  },
  "0x1f39dd2bf5a27e2d4ed691dcf933077371777cb0": {
    "id": "snowcrash-token",
    "circulating_supply": 0.0
  },
  "0x1d3437e570e93581bd94b2fd8fbf202d4a65654a": {
    "id": "nanobyte",
    "circulating_supply": 1289900928.3212829
  },
  "0x1d2f0da169ceb9fc7b3144628db156f3f6c60dbe": {
    "id": "binance-peg-xrp",
    "circulating_supply": 0.0
  },
  "0x1d229b958d5ddfca92146585a8711aecbe56f095": {
    "id": "zoo-crypto-world",
    "circulating_supply": 0.0
  },
  "0x1ce0c2827e2ef14d5c4f29a091d735a204794041": {
    "id": "binance-peg-avalanche",
    "circulating_supply": 2000000.0
  },
  "0x1bf7aedec439d6bfe38f8f9b20cf3dc99e3571c4": {
    "id": "tronpad",
    "circulating_supply": 765212999.98
  },
  "0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3": {
    "id": "binance-peg-dai",
    "circulating_supply": 40999971.51735277
  },
  "0x19e6bfc1a6e4b042fb20531244d47e252445df01": {
    "id": "templardao",
    "circulating_supply": 0.0
  },
  "0x19a4866a85c652eb4a2ed44c42e4cb2863a62d51": {
    "id": "hodooi-com",
    "circulating_supply": 1000000000.0
  },
  "0x190b589cf9fb8ddeabbfeae36a813ffb2a702454": {
    "id": "bdollar",
    "circulating_supply": 0.0
  },
  "0x181de8c57c4f25eba9fd27757bbd11cc66a55d31": {
    "id": "beluga-fi",
    "circulating_supply": 0.0
  },
  "0x17b7163cf1dbd286e262ddc68b553d899b93f526": {
    "id": "qubit",
    "circulating_supply": 0.0
  },
  "0x1796ae0b0fa4862485106a0de9b654efe301d0b2": {
    "id": "polychain-monsters",
    "circulating_supply": 5853813.9522242285
  },
  "0x1785113910847770290f5f840b4c74fc46451201": {
    "id": "fabwelt",
    "circulating_supply": 215068938.85857353
  },
  "0x16939ef78684453bfdfb47825f8a5f714f12623a": {
    "id": "binance-peg-tezos-token",
    "circulating_supply": 0.0
  },
  "0x1633b7157e7638c4d6593436111bf125ee74703f": {
    "id": "splinterlands",
    "circulating_supply": 489718725.3536008
  },
  "0x1613957159e9b0ac6c80e824f7eea748a32a0ae2": {
    "id": "chain-guardians",
    "circulating_supply": 111900000.0
  },
  "0x154a9f9cbd3449ad22fdae23044319d6ef2a1fab": {
    "id": "cryptoblades",
    "circulating_supply": 1000000.0
  },
  "0x151b1e2635a717bcdc836ecd6fbb62b674fe3e1d": {
    "id": "venus-xvs",
    "circulating_supply": 0.0
  },
  "0x14c358b573a4ce45364a3dbd84bbb4dae87af034": {
    "id": "dungeonswap",
    "circulating_supply": 5219233.208266838
  },
  "0x14a9a94e555fdd54c21d7f7e328e61d7ebece54b": {
    "id": "loot",
    "circulating_supply": 13001000.944587374
  },
  "0x14016e85a25aeb13065688cafb43044c2ef86784": {
    "id": "bridged-trueusd",
    "circulating_supply": 2037601.062035829
  },
  "0x0cbd6fadcf8096cc9a43d90b45f65826102e3ece": {
    "id": "checkdot",
    "circulating_supply": 7390041.0
  },
  "0x0b3f42481c228f70756dbfa0309d3ddc2a5e0f6a": {
    "id": "ultrasafe",
    "circulating_supply": 0.0
  },
  "0x0b15ddf19d47e6a86a56148fb4afffc6929bcb89": {
    "id": "idia",
    "circulating_supply": 748389159.8654493
  },
  "0x0a3a21356793b49154fd3bbe91cbc2a16c0457f5": {
    "id": "redfox-labs-2",
    "circulating_supply": 1929656337.827613
  },
  "0x0eb3a705fc54725037cc9e008bdede697f62f335": {
    "id": "cosmos",
    "circulating_supply": 467960691.523058
  },
  "0x0e7beec376099429b85639eb3abe7cf22694ed49": {
    "id": "bunicorn",
    "circulating_supply": 0.0
  },
  "0x0e09fabb73bd3ade0a17ecc321fd13a19e81ce82": {
    "id": "pancakeswap-token",
    "circulating_supply": 345458628.7154215
  },
  "0x0d8ce2a99bb6e3b7db580ed848240e4a0f9ae153": {
    "id": "binance-peg-filecoin",
    "circulating_supply": 0.0
  },
  "0x09f423ac3c9babbff6f94d372b16e4206e71439f": {
    "id": "enjinstarter",
    "circulating_supply": 4137945042.646029
  },
  "0x08ba0619b1e7a582e0bce5bbe9843322c954c340": {
    "id": "binamon",
    "circulating_supply": 170194929.164554
  },
  "0x0864c156b3c5f69824564dec60c629ae6401bf2a": {
    "id": "streamr",
    "circulating_supply": 767121867.0
  },
  "0x08037036451c768465369431da5c671ad9b37dbc": {
    "id": "nft-stars",
    "circulating_supply": 1374249.2708487154
  },
  "0x0782b6d8c4551b9760e74c0545a9bcd90bdc41e5": {
    "id": "helio-protocol-hay",
    "circulating_supply": 37599049.8493389
  },
  "0x076ddce096c93dcf5d51fe346062bf0ba9523493": {
    "id": "paralink-network",
    "circulating_supply": 0.0
  },
  "0x0565805ca3a4105faee51983b0bd8ffb5ce1455c": {
    "id": "blockchainspace",
    "circulating_supply": 455492813.49321496
  },
  "0x04c747b40be4d535fc83d09939fb0f626f32800b": {
    "id": "itam-games",
    "circulating_supply": 0.0
  },
  "0x04baf95fd4c52fd09a56d840baee0ab8d7357bf0": {
    "id": "one",
    "circulating_supply": 0.0
  },
  "0x03ff0ff224f904be3118461335064bb48df47938": {
    "id": "wrapped-one",
    "circulating_supply": 0.0
  },
  "0x0391be54e72f7e001f6bbc331777710b4f2999ef": {
    "id": "trava-finance",
    "circulating_supply": 4332136094.446757
  },
  "0x037838b556d9c9d654148a284682c55bb5f56ef4": {
    "id": "lightning-protocol",
    "circulating_supply": 0.0
  },
  "0x02ff5065692783374947393723dba9599e59f591": {
    "id": "yooshi",
    "circulating_supply": 0.0
  },
  "0x02a40c048ee2607b5f5606e445cfc3633fb20b58": {
    "id": "kaby-arena",
    "circulating_supply": 0.0
  },
  "0x0288d3e353fe2299f11ea2c2e1696b4a648ecc07": {
    "id": "zcore-finance",
    "circulating_supply": 0.0
  },
  "0x0255af6c9f86f6b0543357bacefa262a2664f80f": {
    "id": "immutable",
    "circulating_supply": 0.0
  },
  "0x0231f91e02debd20345ae8ab7d71a41f8e140ce7": {
    "id": "jupiter",
    "circulating_supply": 1000000000.0
  },
  "0x016cf83732f1468150d87dcc5bdf67730b3934d3": {
    "id": "airnft-token",
    "circulating_supply": 0.0
  },
  "0x00e1656e45f18ec6747f5a8496fd39b50b38396d": {
    "id": "bomber-coin",
    "circulating_supply": 87720504.5823333
  },
  "0x4437743ac02957068995c48e08465e0ee1769fbe": {
    "id": "fortress",
    "circulating_supply": 9522044.46777561
  },
  "0x47c454ca6be2f6def6f32b638c80f91c9c3c5949": {
    "id": "games-for-a-living",
    "circulating_supply": 5253416643.0
  },
  "0x8263cd1601fe73c066bf49cc09841f35348e3be0": {
    "id": "altura",
    "circulating_supply": 990000000.0
  },
  "0x868fced65edbf0056c4163515dd840e9f287a4c3": {
    "id": "sign-global",
    "circulating_supply": 1350000000.0
  },
  "0x14778860e937f509e651192a90589de711fb88a9": {
    "id": "cyberconnect",
    "circulating_supply": 48878133.733333334
  }
}

    for data in supplies.values():
        if data['id'] == coingecko_id:
            return float(data['circulating_supply'])


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
    locked_or_burned_supply = 0
    c_supply = 0
    for holder,balance in config.tqdm(holders.items(), desc="Calculating Circulating Supply", unit="address"):
        #Balances are RAW
        if islocker(holder,chain) or isburner(holder,chain,creation_blocknum = 0,last_block = 0):
            locked_or_burned_supply += balance
        else:
            c_supply += balance
    
    circulating = total_supply - locked_or_burned_supply
    return circulating if circulating > 0 else 0.0  # avoid negatives

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

    class RateLimiter:
        def __init__(self, max_calls, period):
            self.lock = config.Lock()
            self.max_calls = max_calls
            self.period = period
            self.calls = []

        def acquire(self):
            with self.lock:
                now = config.time.time()
                self.calls = [t for t in self.calls if now - t < self.period]
                if len(self.calls) >= self.max_calls:
                    time_to_wait = self.period - (now - self.calls[0])
                    if time_to_wait > 0:
                        config.time.sleep(time_to_wait)
                self.calls.append(config.time.time())

    logs_rate_limiter = RateLimiter(max_calls=1, period=2.0)  # Allow 1 log query every 2 seconds

    pair_address = web3.to_checksum_address(pair_address)

    # Estimate 24h block range
    blocks_per_day = 28800 if chain == "bsc" else 6500
    from_block = max(latest_block - blocks_per_day, 0)

    # Swap event signature hash
    swap_event_sig = "0x" + web3.keccak(text="Swap(address,uint256,uint256,uint256,uint256,address)").hex()

    MAX_BLOCK_RANGE = 1000  # adjust if needed based on provider limits

    logs = []
    current_from = from_block
    MAX_RETRIES = 5
    RETRY_DELAY = 2  # base delay in seconds

    while current_from <= latest_block:
        current_to = min(current_from + MAX_BLOCK_RANGE - 1, latest_block)
        for attempt in range(MAX_RETRIES):
            try:
                logs_rate_limiter.acquire()  # rate limit before each call
                chunk_logs = web3.eth.get_logs({
                    "fromBlock": current_from,
                    "toBlock": current_to,
                    "address": pair_address,
                    "topics": [swap_event_sig],
                })
                logs.extend(chunk_logs)
                break  # success, exit retry loop
            except Exception as e:
                if "429" in str(e) and attempt < MAX_RETRIES - 1:
                    wait_time = RETRY_DELAY ** (attempt + 1)
                    print(f"⚠️ Rate limited fetching logs {current_from}-{current_to}. Retrying in {wait_time}s...")
                    config.time.sleep(wait_time)
                else:
                    print(f"❌ Failed to fetch logs from {current_from} to {current_to}: {e}")
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
            decoded = config.decode_abi(["uint256", "uint256", "uint256", "uint256"], bytes.fromhex(data[2:]))
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
    with open("data/addresses-darklist.json", encoding="utf-8", errors="replace") as f:
        address_blacklist = config.json.load(f)

    with open("data/urls-darklist.json", encoding="utf-8", errors="replace") as f:
        url_blacklist = config.json.load(f)

    if chain == 'bsc':
        with open("data/bsc-blacklist.json", encoding="utf-8", errors="replace") as f:
            scammers_blacklist = config.json.load(f)
    elif chain == 'eth':
        with open("data/ethereum-blacklist.json", encoding="utf-8", errors="replace") as f:
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
            if blacklisted["id"] in found_url:
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
    
    with open(json_filename, 'w', encoding="utf-8") as f:
        config.json.dump(results, f, indent=4)

    print(f"\n✅ Analysis complete!")
    print(f"📝 Report saved to: {report_filename}")
    print(f"📊 JSON data saved to: {json_filename}")
    
    return results
