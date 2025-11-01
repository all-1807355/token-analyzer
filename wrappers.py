import config
import utils

def lifecycle_analysis(token_address: str, chain: str, results: dict, report_lines: list, pbar=None):
    print("\n🔍 Running lifecycle analysis...")
    results['analyses']['lifecycle'] = {
        'token_age_seconds': None,
        'token_creation_date': None,
        'creation_to_first_trade_seconds': None,
        'creation_to_first_trade_blocks': None,
        'last_tx_hash': None,
        'last_active_age': None,
        'inactive_days': None
    }
    report_lines.append("\nLifecycle Analysis\n-------------\n")
    try:
        token_age = utils.get_token_age(token_address, chain)
        #check if token age is null
        if not token_age:
            error_msg = "Lifecycle information unavailable: Could not get token age."
            #results.setdefault('analyses', {}).setdefault('lifecycle', {}).setdefault('token_age_seconds',None)
            report_lines.append(f"⚠️ Lifecycle analysis error: {error_msg}\n")
            # if pbar:
            #     pbar.update(4)
            # return results, report_lines

        creation_trade_delay = utils.get_creation_to_first_trade_delay(token_address, chain)
        if not creation_trade_delay:
            error_msg = "Lifecycle information unavailable: Could not get delay from creation to first trade."
            # results.setdefault('analyses', {}).setdefault('lifecycle', {}).setdefault('token_creation_date',None)
            report_lines.append(f"⚠️ Lifecycle analysis error: {error_msg}\n")
            # if pbar:
            #     pbar.update(4)
            # return results, report_lines
        
        time_since_last_tx = utils.last_active_age(token_address,chain)
        if not time_since_last_tx:
            error_msg = "Lifecycle information unavailable: Could not get time since last transaction."
            # results.setdefault('analyses', {}).setdefault('lifecycle', {}).setdefault()
            report_lines.append(f"⚠️ Lifecycle analysis error: {error_msg}\n")
            # if pbar:
            #     pbar.update(4)
            # return results, report_lines
        
        results['analyses']['lifecycle'] = {
            'token_age_seconds': token_age,
            'token_creation_date': creation_trade_delay.get("creation_date"),
            'creation_to_first_trade_seconds': creation_trade_delay.get("time_delay_seconds"),
            'creation_to_first_trade_blocks' : creation_trade_delay.get("block_delay"),
            'last_tx_hash': time_since_last_tx.get("last_tx_hash"),
            'last_active_age': time_since_last_tx.get("last_active_utc"),
            'inactive_days': time_since_last_tx.get("inactive_days")
        }

        report_lines.append(f"Token Age: {token_age/86400:.2f} days\n")
        if creation_trade_delay:
            report_lines.append(f"Time to First Trade: {creation_trade_delay.get('time_delay_seconds')/3600:.2f} hours\n")
            report_lines.append(f"Blocks to First Trade: {creation_trade_delay.get('block_delay')}\n")
            report_lines.append(f"Token Creation Date: {creation_trade_delay.get('creation_date')}\n")
        if time_since_last_tx:
            report_lines.append(f"Last Active: {time_since_last_tx.get('last_active_utc')}\n")
            report_lines.append(f"Days Since Last Activity: {time_since_last_tx.get('inactive_days')} days\n")
            report_lines.append(f"Last Transaction Hash: {time_since_last_tx.get('last_tx_hash')}\n")
        else:
            report_lines.append("⚠️ Could not determine last active transaction.\n")
        if pbar:
            pbar.update(4)

    except Exception as e:
        tb = e.__traceback__
        # Walk to the last frame in the traceback (where the error actually happened)
        while tb.tb_next:
            tb = tb.tb_next
        func_name = tb.tb_frame.f_code.co_name
        error_msg = f"Exception during lifecycle analysis in {func_name}: {e}"
        # results.setdefault('analyses', {}).setdefault('lifecycle', {})['error'] = error_msg
        report_lines.append(f"⚠️ Lifecycle analysis exception: {error_msg}\n")
        if pbar:
            pbar.update(4)
    return results, report_lines

def security_analysis(token_address: str, chain: str, results: dict, report_lines: list, pbar=None):
    print("\n🔍 Running security analysis...")
    results['analyses']['security'] = {
        "warnings": None,
        "homany_warnings": 0,
        "suspicious_urls": None,
        "howmany_suspicious_urls": 0,
        "suspicious_addresses": None,
        "howmany_suspicious_addresses": 0
    }
    report_lines.append("\nSecurity Analysis\n-----------------\n")
    try:
        source_code = results['analyses']['contract'].get('source_code')
        if not source_code:
            contract_info = utils.get_contract_info(token_address, chain)
            source_code = contract_info.get('source_code')
        security_report = utils.run_security_checks(token_address, chain,source_code) if source_code else None
        if not security_report:
            error_msg = "Security analysis data not available."
            results.setdefault('analyses', {}).setdefault('security', {})['error'] = error_msg
            report_lines.append(f"⚠️ Security analysis error: {error_msg}\n")
            # if pbar:
            #     pbar.update(5)
            # return results, report_lines
        
        #results['analyses']['security'] = security_report
        if security_report:
            results['analyses']['security']["warnings"] = security_report.get('warnings', []) 
            results['analyses']['security']["howmany_warnings"] = len(security_report.get('warnings', []))
            
            results['analyses']['security']['suspicious_urls'] = security_report.get('suspicious_urls', {})
            results['analyses']['security']['howmany_suspicious_urls'] = len(security_report.get('suspicious_urls', []))
            
            results['analyses']['security']['suspicious_addresses'] = security_report.get('suspicious_addresses', {}) 
            results['analyses']['security']['howmany_suspicious_addresses'] = len(security_report.get('suspicious_addresses', []))


            if 'warnings' in security_report and security_report.get('warnings'):
                report_lines.append("⚠️ Warning: Potentially risky address found.\n")
                for warning in security_report['warnings']:
                    report_lines.append(f"  Address: {warning['address']}, Comment: {warning['comment']}\n")
            
            if 'suspicious_urls' in security_report and security_report.get('suspicious_urls'):
                report_lines.append("⚠️ Suspicious URL(s) found in the contract.\n")
                for url, comment in security_report['suspicious_urls'].items():
                    report_lines.append(f"  URL: {url}, Reason: {comment}\n")
            
            if 'suspicious_addresses' in security_report and security_report.get('suspicious_addresses'):
                report_lines.append("⚠️ Suspicious address(es) found in the contract.\n")
                for token, address in security_report['suspicious_addresses'].items():
                    report_lines.append(f"  Token: {token}, Suspicious Address: {address}\n")

        if pbar:
            pbar.update(5)

    except Exception as e:
        tb = e.__traceback__
        # Walk to the last frame in the traceback (where the error actually happened)
        while tb.tb_next:
            tb = tb.tb_next
        func_name = tb.tb_frame.f_code.co_name
        error_msg = f"Exception during security analysis in {func_name}: {e}"
        results.setdefault('analyses', {}).setdefault('security', {})['error'] = error_msg
        report_lines.append(f"⚠️ Security analysis exception in {func_name}: {error_msg}\n")
        if pbar:
            pbar.update(5)
    return results, report_lines

def liquidity_analysis(token_address: str, chain: str, results: dict, report_lines: list, web3,pbar=None):
    print("\n🔍 Running liquidity analysis...")
    results['analyses']['liquidity'] = {
            'price_usd': None,
            'liquidity_usd': None,
            "slippage_is_suspicious": None,
            "first_abnormal_slippage_percent": None,
            "first_abnormal_slippage_fixed": None,
            'market_cap_usd': None,
            'liquidity_to_market_cap_ratio': None,
            'token_volume': None,
            'volume_usd': None,
            'volume_to_liquidity_ratio': None,
            "locked_liquidity_percent": None,
            "locked_95_for_15_days": None,
            "creator_under_5_percent": None,
            "creator_percent_of_lp": None,
            "owner_under_5_percent": None,
            "owner_percent_of_lp": None,
            "total_lp_supply": None,
            "lp_holders_count": None,
            "lp_holders": None 
        }
    report_lines.append("\nLiquidity Analysis\n-----------------\n")
    try:
        lp_address, pair_abi = utils.get_lp_pair(token_address,chain,web3)
        data = None#utils.get_dexscreener_price_liquidity_volume(token_address)
        price = None
        liquidity = None
        creation = None
        total_lp_supply = None
        if data:
            price = data[0]
            liquidity = data[1]
            dexscreenerok = True
        else:
            dexscreenerok = False
            data = utils.get_price_and_liquidity(lp_address, token_address, chain, web3)
            if data:
                price = data.get('price_usd')
                liquidity = data.get('liquidity_usd')
            else:
                report_lines.append(f"⚠️ ERROR: no pair token data found!")
                price = None
                liquidity = None
        total_c_supply = results['analyses']['holder'].get('total_circulating_supply')
        total_supply = results['analyses']['holder'].get('total_supply')
        #TODO FIX
        if total_c_supply == None:
            coingecko_id = utils.get_coingecko_id_from_contract(token_address, chain)
            if coingecko_id != None:
                total_c_supply = utils.get_circulating_supply(coingecko_id)
            elif coingecko_id == None:
                holders = results['analyses']['holder'].get('holders_list',None)
                if holders == None:
                    #holders = utils.get_unique_token_holders_moralis(token_address,chain,decimals)
                    if holders == None:
                        creation = utils.get_contract_creation_tx(token_address, chain)
                        creation_block = int(creation["blocknum"]) if creation else None
                        last_tx = utils.get_latest_tx(token_address,chain)
                        last_block = int(last_tx['blockNumber']) if last_tx else None
                        abi = results['analyses']['contract'].get('abi',utils.get_contract_info(token_address,chain)['abi'])
                        holders = utils.get_unique_token_holders_API(token_address,chain)
                        if not holders:
                            holders = utils.get_unique_token_holders_web3(token_address,chain,web3,abi,creation_block,last_block)
                            if holders == None:
                                error_msg = "Failed to retrieve holders data."
                                # results.setdefault('analyses', {}).setdefault('holders', {})['error'] = error_msg
                                report_lines.append(f"⚠️ Liquidity analysis error: {error_msg}\n")
                total_supply = utils.get_total_supply_API(token_address,chain)
                decimals = utils.get_token_decimals(token_address,web3)
                if total_supply:
                    total_supply = total_supply / (10 ** decimals)
                elif total_supply == None:
                    total_supply = utils.get_total_supply_web3(token_address,web3,decimals)
                total_c_supply = utils.get_circulating_supply_estimate(token_address,chain,total_supply,holders)
        
        if creation == None:
            creation = utils.get_contract_creation_tx(lp_address,chain)
        if creation['timestamp'] and creation['blocknum']:
            creation_timestamp = creation["timestamp"]
            creation_blocknum = int(creation["blocknum"])
        else:
            creation_timestamp = None
            creation_blocknum = None
        #goplus api to get liquidity data
        liquidity_status = utils.analyze_lp_security(token_address,chain)
        if not liquidity_status:
            error_msg = "Liquidity pool info could not be retrieved."
            results.setdefault('analyses', {}).setdefault('liquidity', {})['error'] = error_msg
            report_lines.append(f"⚠️ Liquidity analysis error: {error_msg}\n")
            if pbar:
                pbar.update(5)
            return results, report_lines
            
        liquidity_holders = liquidity_status["lp_holders"]
        if lp_address:
            last_block = utils.get_latest_tx(lp_address,chain)
            if last_block != None:
                last_block = int(last_block['blockNumber'])
        else:
            last_block = None
        # WITHOUT API YOU WOULD USE THE ONE BELOW
        #TODO compute the time difference between the two. 
        # liquidity_holders = utils.get_lp_holders(lp_address, web3, pair_abi, creation_blocknum,last_block)
        if last_block and price and liquidity and not dexscreenerok:
            # print(web3,lp_address,last_block,chain,price,liquidity)
            fres = utils.get_volume_to_liquidity_ratio(web3,lp_address,last_block,chain,float(price),float(liquidity))
            token_volume = fres['token_volume']
            vol_liq_ratio = fres['vol_liq_ratio']
            volume_24h = fres['volume_usd']
        elif last_block and price and liquidity and dexscreenerok:
            fres = utils.get_volume_to_liquidity_ratio(web3,lp_address,last_block,chain,float(price),float(liquidity))
            token_volume = fres['token_volume']
            vol_liq_ratio = fres['vol_liq_ratio']
            volume_24h = fres['volume_usd'] #TODO check docs
        else:
            token_volume = None
            vol_liq_ratio = None
            volume_24h = None
        
        if price and liquidity: 
            liq_market_ratio = utils.get_liquidity_to_marketcap_ratio(total_c_supply,float(price),float(liquidity))
            market_cap_usd = liq_market_ratio['market_cap_usd']
            liquidity_to_market_cap_ratio = liq_market_ratio['liquidity_to_market_cap_ratio']
        else: 
            liq_market_ratio = None
            liquidity_to_market_cap_ratio = None
            market_cap_usd = None

        
        # lp_contract = web3.eth.contract(address=config.Web3.to_checksum_address(lp_address), abi=pair_abi)
        if liquidity_status.get('total_lp_supply',None):
            total_lp_supply = liquidity_status['total_lp_supply']
        elif not total_lp_supply:
            total_lp_supply = utils.get_total_supply_API(lp_address, chain)
            if total_lp_supply:
                decimals = utils.get_token_decimals(lp_address,web3)
                total_lp_supply = total_lp_supply / (10 ** decimals)
        
        slippage_stats = utils.is_token_suspicious_by_slippage(token_address,chain,web3,lp_address,pair_abi)
        if slippage_stats == None:
            slippage_stats = {
                "is_suspicious": None,
                "first_abnormal_slippage_percent": None,
                "first_abnormal_slippage_fixed": None
            }
        # total_lp_supply = utils.get_total_supply_API(token_address,chain)
        owner = results["analyses"]["contract"].get("owner",utils.get_owner(token_address, web3))
        #owner_lp_balance = lp_address.functions.balanceOf(owner).call()
        creator = results["analyses"]["contract"].get("creator",utils.get_creator(token_address, chain))
        results['analyses']['liquidity'] = {
            'price_usd': price,
            'liquidity_usd': liquidity,
            "slippage_is_suspicious": slippage_stats['is_suspicious'],
            "first_abnormal_slippage_percent": slippage_stats['first_abnormal_slippage_percent'],
            "first_abnormal_slippage_fixed": slippage_stats['first_abnormal_slippage_fixed'],
            'market_cap_usd': market_cap_usd,
            'liquidity_to_market_cap_ratio': liquidity_to_market_cap_ratio,
            'token_volume': token_volume,
            'volume_usd': volume_24h,
            'volume_to_liquidity_ratio': vol_liq_ratio,
            "locked_liquidity_percent": liquidity_status['locked_liquidity_percent'],
            "lock_duration": liquidity_status['lock_duration'],
            "locked_95_for_15_days": liquidity_status['locked_95_for_15_days'],
            "creator_under_5_percent": liquidity_status['creator_under_5_percent'],
            "creator_percent_of_lp": liquidity_status['creator_percent_of_lp'],
            "owner_under_5_percent": liquidity_status['owner_under_5_percent'],
            "owner_percent_of_lp": liquidity_status['owner_percent_of_lp'],
            "total_lp_supply": liquidity_status['total_lp_supply'],
            "lp_holders_count": liquidity_status['lp_holders_count'],
            "lp_holders": liquidity_holders
        }
        
        if liq_market_ratio:
            report_lines.append(f"Market Cap: ${liq_market_ratio['market_cap_usd']:,.2f}\n")
            report_lines.append(f"Liquidity: ${liquidity:,.2f}\n")
            report_lines.append(f"Liquidity/MCap Ratio: {liq_market_ratio['liquidity_to_market_cap_ratio']:.4f}\n")
        if vol_liq_ratio:
            report_lines.append(f"Token Volume: {fres['token_volume']:.4f}\n")
            report_lines.append(f"USD Volume: {fres['volume_usd']:.4f}\n")
            report_lines.append(f"24h Volume/Liquidity Ratio: {fres['vol_liq_ratio']:.4f}\n")
        if liquidity_status:
            report_lines.append(f"Percentage of liquidity locked: {liquidity_status['locked_liquidity_percent']:.4f}\n")
            report_lines.append(f"Was 95% of liquidity locked for more than 15 days?: {liquidity_status['locked_95_for_15_days']}\n")
            report_lines.append(f"Secure\n" if {liquidity_status['locked_95_for_15_days']} else "Unverified or Unlocked\n")
            report_lines.append(f"Creator owns under 5% of LP tokens: {liquidity_status['creator_under_5_percent']} ({liquidity_status['creator_percent_of_lp']})\n")
            report_lines.append(f"Total supply of LP tokens: {liquidity_status['total_lp_supply']}\n")
            report_lines.append(f"LP holders count: {liquidity_status['lp_holders_count']}\n")
            report_lines.append(f"\r\n")
 
            report_lines.append(f"Liquidity holders for {token_address}, ({results["token_name"] if results["token_name"] else utils.get_token_name(token_address,chain)})\n")
            # if total_lp_supply is None:
            #     total_lp_supply = lp_contract.functions.totalSupply().call()
            for holder in liquidity_holders:
                if holder["address"] == owner:
                    report_lines.append(f"\r\nOwner {holder["address"]} holds {holder["balance"]} LP tokens\r\n")
                    owner_lp_balance = holder["balance"]
                    #check if owner holds less than 5% of liquidity...
                    if total_lp_supply != None and (owner_lp_balance / total_lp_supply) * 100 > 5:
                        if owner == creator:
                            print(f"WARNING: Owner/Creator holds over 5% of the liquidity")
                            report_lines.append(f"WARNING: Owner/Creator holds over 5% of the liquidity")
                        print(f"WARNING: Owner holds over 5% of the liquidity")
                        report_lines.append(f"WARNING: Owner holds over 5% of the liquidity")
                elif holder == creator:
                    report_lines.append(f"\r\nCreator {holder["address"]} holds {holder["balance"]} LP tokens\r\n")
                    creator_lp_balance = holder["balance"]
                    #check if creator holds less than 5% of liquidity...
                    if total_lp_supply != None and (creator_lp_balance / total_lp_supply) * 100 > 5:
                        print(f"WARNING: Creator holds over 5% of the liquidity")
                        report_lines.append(f"WARNING: Creator holds over 5% of the liquidity")
                else: report_lines.append(f"\r\n{holder["address"]} holds {holder["balance"]} LP tokens\r\n")

        if not liq_market_ratio or not vol_liq_ratio or not liquidity_status:
            error_msg = "Liquidity pool info could not be retrieved."
            results.setdefault('analyses', {}).setdefault('liquidity', {})['error'] = error_msg
            report_lines.append(f"⚠️ Liquidity analysis error: {error_msg}\n")
            if pbar:
                pbar.update(5)
            return results, report_lines

        if pbar:
            pbar.update(5)

    except Exception as e:
        tb = e.__traceback__
        # Walk to the last frame in the traceback (where the error actually happened)
        while tb.tb_next:
            tb = tb.tb_next
        func_name = tb.tb_frame.f_code.co_name
        error_msg = f"Exception during liquidity analysis in {func_name}: {e}"
        results.setdefault('analyses', {}).setdefault('liquidity', {})['error'] = error_msg
        report_lines.append(f"⚠️ Liquidity analysis exception in {func_name}: {error_msg}\n")
        if pbar:
            pbar.update(5)
    return results, report_lines

def holder_analysis(token_address: str, chain: str, results: dict, report_lines: list, web3, pbar=None):
    print("\n🔍 Running holder analysis...")
    results['analyses']['holder'] = {
        'total_holders': 0,
        'holders_list': None,
        'total_supply': 0.0,
        'total_circulating_supply': 0.0,
        'owner': None,
        'creator': None,
        'holders_exceeding_5_percent_circulating': None,
        'howmany_holders_exceeding_5_percent_circulating': 0,
        'top_10_holders': None,
        'total_top_10_balance': None,
        'top10_percentage_of_total_supply': None,
        'top10_percentage_of_circulating_supply': None,
        'top_10_less_than_70_percent_of_total': None,
        'top_10_less_than_70_percent_of_circulating': None
    }
    report_lines.append("\nHolder Analysis\n--------------\n") 
    try:
        abi = results['analyses']['contract'].get('abi',None)
        if abi == None:
            abi = utils.get_contract_info(token_address,chain).get('abi')
            if not abi:
                error_msg = "ABI not found or contract info unavailable for holder analysis."
                report_lines.append(f"⚠️ Holder analysis error: {error_msg}\n")
        
        decimals = utils.get_token_decimals(token_address,web3)
        #NOTE only use others when moralis is not useable
        holders_list = None
        #holders_list = utils.get_unique_token_holders_moralis(token_address, chain,decimals)
        if not holders_list:
            holders_list = utils.get_unique_token_holders_API(token_address,chain,decimals)
            if not holders_list:
                if not holders_list and abi != None:
                    creation = utils.get_contract_creation_tx(token_address, chain)
                    creation_block = int(creation["blocknum"]) if creation else None
                    last_tx = utils.get_latest_tx(token_address,chain)
                    last_block = int(last_tx['blockNumber']) if last_tx else None
                    holders_list = utils.get_unique_token_holders_web3(token_address,chain,web3,decimals,abi,creation_block,last_block) if creation_block and last_block and abi else None
                    if holders_list == None:
                        error_msg = "Failed to retrieve holders data."
                        # results.setdefault('analyses', {}).setdefault('holders', {})['error'] = error_msg
                        report_lines.append(f"⚠️ Holder analysis error: {error_msg}\n")
        if holders_list == None:
            holders_list = {}
        # lockandburn = utils.find_all_lockers_and_burners(token_address, chain, holders_list, web3)
        # # Extract address strings from the dicts
        # locker_addresses = {entry["address"] for entry in lockandburn["lockers"]}
        # burner_addresses = {entry["address"] for entry in lockandburn["burners"]}

        # # Remove lockers and burners from holders_list
        # for holder in list(holders_list.keys()):
        #     if holder in locker_addresses or holder in burner_addresses:
        #         del holders_list[holder]
        
        total_supply = utils.get_total_supply_API(token_address,chain) #RAW not normalized
        if total_supply:
            total_supply = total_supply / (10 ** decimals) #Normalized total_supply
        elif total_supply == None:
            total_supply = utils.get_total_supply_web3(token_address,web3,decimals)

        coingecko_id = utils.get_coingecko_id_from_contract(token_address, chain)
        if coingecko_id != None:
            total_c_supply = utils.get_circulating_supply(coingecko_id) #Already normalized
        elif holders_list:
            total_c_supply = utils.get_circulating_supply_estimate(token_address, chain, total_supply, holders_list)
        else: 
            total_c_supply = total_supply
        owner = results['analyses']['contract'].get('owner')
        creator = results['analyses']['contract'].get('creator')
        owner = owner or utils.get_owner(token_address, web3)
        creator = creator or utils.get_creator(token_address, chain)
        owner_percentage = owner_flag = None
        creator_percentage = creator_flag = None
        if owner:
            owner_percentage, owner_flag = utils.owner_circulating_supply_analysis(token_address, chain, owner, total_c_supply, web3, abi)

        if creator:
            if creator == owner:
                creator_percentage, creator_flag = owner_percentage, owner_flag
            else:
                creator_percentage, creator_flag = utils.owner_circulating_supply_analysis(token_address, chain, creator, total_c_supply, web3, abi)
        holder_analysis_results = utils.holder_circulating_supply_analysis(holders_list, total_c_supply,owner,creator,decimals)
        #     result = {
        #     'flagged_holders': flagged_holders,
        #     'summary': {
        #         'total_holders_checked': len(holders),
        #         'holders_exceeding_5_percent': len(flagged_holders),
        #         'compliant': len(flagged_holders) == 0
        #     }
        # }
        top10_analysis_results = utils.top10_analysis(holders_list,total_supply, total_c_supply)
        #     result = {
        #     'top_10_holders': top_10_data,
        #     'totals': {
        #         'total_top_10_balance': total_top_10_balance,
        #         'percentage_of_circulating_supply': percentage_circ_total,
        #         'percentage_of_total_supply': percentage_total_supply,
        #         'top_10_less_than_70_percent_circulating': percentage_circ_total < 70
        #     }
        # }
        # print(f"Debug: Storing holders list with length: {len(holders_list) if holders_list else 'None'}")
        enriched_dict = {}
        owner_dict = {}
        creator_dict = {}
        for address, balance in holders_list.items():
            # age,age_readable = utils.get_holder_age(token_address, chain,address).values()
            enriched_dict[address] = {
                'balance': balance if balance else 0.0,
                # 'age': age,
                # 'age_readable': age_readable,
                'percentage_of_total_supply': (balance / total_supply) * 100 if total_supply else 0.0,
                'percentage_of_circulating_supply': (balance / total_c_supply) * 100 if total_c_supply else 0.0
            }
            if owner is not None and address.lower() == owner.lower():
                owner_dict = {
                    'address': owner,
                    'balance': balance if balance else 0.0,
                    # 'age':age,
                    # 'age_readable': age_readable,
                    'percentage_of_circulating_supply': owner_percentage,
                    'exceeds_5_percent': owner_flag
                }
            if creator is not None and address.lower() == creator.lower():
                creator_dict = {
                    'address': creator,
                    'balance': balance if balance else 0.0,
                    # 'age':age,
                    # 'age_readable': age_readable,
                    'percentage_of_circulating_supply': creator_percentage,
                    'exceeds_5_percent': creator_flag
                }

        results['analyses']['holder'] = {
            'total_holders': len(holders_list),
            'holders_list': enriched_dict,
            'total_supply': total_supply if total_supply else 0.0,
            'total_circulating_supply': total_c_supply if total_c_supply else 0.0,
            'owner': owner_dict,
            'creator': creator_dict,
            'holders_exceeding_5_percent_circulating': holder_analysis_results['flagged_holders'],
            'howmany_holders_exceeding_5_percent_circulating': holder_analysis_results['summary']['holders_exceeding_5_percent'],
            'top_10_holders': top10_analysis_results['top_10_holders'],
            'total_top_10_balance': top10_analysis_results['totals']['total_top_10_balance'] / (10**decimals) if top10_analysis_results['totals']['total_top_10_balance'] else 0.0,
            'top10_percentage_of_total_supply': top10_analysis_results['totals']['total_top_10_percentage_of_total_supply'],
            'top10_percentage_of_circulating_supply': top10_analysis_results['totals']['total_top_10_percentage_of_circulating_supply'],
            'top_10_less_than_70_percent_of_total': top10_analysis_results['totals']['top_10_less_than_70_percent_total_supply'],
            'top_10_less_than_70_percent_of_circulating': top10_analysis_results['totals']['top_10_less_than_70_percent_circulating']
        }  

        # Report Owner Section
        owner_data = results['analyses']['holder'].get('owner')
        creator_data = results['analyses']['holder'].get('creator')
        
        report_lines.append(f"Total Unique Holders: {len(holders_list)}\n")

        if owner_data:
            report_lines.append(f"Owner Address: {owner_data.get('address', 'Unknown')}\n")
            report_lines.append(f"Owner Balance: {owner_data.get('balance', 0):,} tokens\n")
            report_lines.append(f"Owner Share: {owner_data.get('percentage_of_supply', 0):.2f}% of circulating supply\n")
            if owner_data.get('exceeds_5_percent', False):
                report_lines.append("⚠️ Owner holds MORE than 5% of circulating supply\n")
            else:
                report_lines.append("✅ Owner holds LESS than 5% of circulating supply\n")
        else:
            report_lines.append("⚠️ Owner information is not available (possibly hidden or unverified)\n")
        
        if creator_data:
            report_lines.append(f"Owner Address: {creator_data.get('address', 'Unknown')}\n")
            report_lines.append(f"Owner Balance: {creator_data.get('balance', 0):,} tokens\n")
            report_lines.append(f"Owner Share: {creator_data.get('percentage_of_supply', 0):.2f}% of circulating supply\n")
            if creator_data.get('exceeds_5_percent', False):
                report_lines.append("⚠️ Creator holds MORE than 5% of circulating supply\n")
            else:
                report_lines.append("✅ Creator holds LESS than 5% of circulating supply\n")
        else:
            report_lines.append("⚠️ Creator information is not available (possibly hidden or unverified)\n")

        res = results['analyses']['holder']

        if res.get('holders_exceeding_5_percent'):
            over_5 = res.get('howmany_holders_exceeding_5_percent', 0)
            compliant = over_5 == 0
            report_lines.append(f"Holders >5%: {over_5}\n")
            report_lines.append("✅ All holders under 5% threshold\n" if compliant else "⚠️ Some holders exceed 5% of supply\n")
        else:
            report_lines.append("⚠️ Holder analysis summary data is missing\n")
        
        if res.get('top_10_holders'):
            report_lines.append("\nTop 10 Token Holders:\n")
            for i, h in enumerate(res.get('top_10_holders'), start=1):
                addr = h.get('address', 'Unknown')
                bal = h.get('balance', 0)
                pct = h.get('percentage_of_circulating_supply', 0)
                report_lines.append(f"  {i}. {addr} — {bal:,} tokens ({pct:.2f}% of circulating supply)\n")

            tot = res.get('total_top_10_balance',None)
            circ_pct = res.get('top10_percentage_of_circulating_supply', None)
            total_pct = res.get('top10_percentage_of_total_supply', None)
            less_than_70 = res.get('top_10_less_than_70_percent_circulating', True)

            report_lines.append(f"\nTop 10 Total Balance: {tot:,} tokens\n")
            report_lines.append(f"Top 10 Share of Circulating Supply: {circ_pct:.2f}%\n")
            report_lines.append(f"Top 10 Share of Total Supply: {total_pct:.2f}%\n")
            report_lines.append("✅ Top 10 holders control LESS than 70% of circulating supply\n" if less_than_70 else "⚠️ Top 10 holders control MORE than 70% of circulating supply\n")
        else:
            report_lines.append("⚠️ Top 10 holder analysis is not available\n")

        if pbar:
            pbar.update(12)

    except Exception as e:
        tb = e.__traceback__
        # Walk to the last frame in the traceback (where the error actually happened)
        while tb.tb_next:
            tb = tb.tb_next
        func_name = tb.tb_frame.f_code.co_name
        error_msg = f"Exception during holder analysis in {func_name}: {e}"
        results.setdefault('analyses', {}).setdefault('holders', {})['error'] = error_msg
        report_lines.append(f"⚠️ Holder analysis exception in {func_name}: {error_msg}\n")
        if pbar:
            pbar.update(12)

    return results, report_lines

def contract_analysis(token_address: str, chain: str, results: dict, report_lines: list, web3, pbar=None):
    print("\n🔍 Running contract analysis...")
    results['analyses']['contract'] = {
            "contract_name": None,
            "compiler_version": None,
            "license_type": None,
            "implementation": None,
            "source_code": None,
            "abi": None,
            'verified': None,
            'owner': None,
            'creator': None,
            'is_hidden_owner': None,
            'is_proxy': None,
            'is_sellable': None,
            'is_hardcoded_owner': None,
            'code_analysis': {
                'total_matches' : 0,
                'patterns_found' : {}
            }
        }
    report_lines.append("Contract Analysis\n-----------------\n")
    try:
        contract_info = utils.get_contract_info(token_address, chain)
        if not contract_info:
            error_msg = "Contract information or ABI not available/publicly accessible."
            # results.setdefault('analyses', {}).setdefault('contract', {})['error'] = error_msg
            report_lines.append(f"⚠️ Contract analysis error: {error_msg}\n")
            if pbar: pbar.update(6)  # update steps you expect contract analysis to take
            return results, report_lines
        
        sellable = utils.is_token_sellable(token_address, chain)
        if contract_info.get('source_code') != None:
            hardcoded = utils.is_hardcoded_owner(token_address, chain,contract_info['source_code'])
        else:
            hardcoded = None
        owner = utils.get_owner(token_address, web3)
        creator = utils.get_creator(token_address, chain)

        report_lines.append(f"Verified: {'Yes' if contract_info['verified'] else 'No'}\n")
        report_lines.append(f"Is Proxy: {'Yes' if contract_info['is_proxy'] else 'No'}\n")
        report_lines.append(f"Owner Address: {results['analyses']['contract']['owner'] if results.get('analyses').get('contract').get('owner') else "Owner Address not found\n"}\n")
        report_lines.append(f"Creator Address: {results['analyses']['contract']['creator'] if results.get('analyses').get('contract').get('creator') else "Creator Address not found\n"}\n")
        report_lines.append(f"Is sellable (no honeypot): {'Yes' if sellable else 'No'}\n")
        report_lines.append(f"Is owner hardcoded: {'Yes' if hardcoded else 'No'}\n")

        # Enhanced code analysis section
        if contract_info.get('source_code') != None:
            analysis = utils.analyze_token_contract_with_snippets(contract_info['source_code'], pbar=pbar)
            report_lines.append("\nCode Analysis Findings:\n")
            
            if analysis and analysis.get('patterns_found'):
                for category, data in analysis['patterns_found'].items():
                    if data.get('count', 0) > 0:
                        report_lines.append(f"\nWARNING: Found {data['count']} {category.replace('_', ' ').title()} pattern(s):\n")
                        for snippet in data['snippets']:
                            report_lines.append(f"  Pattern matched: {snippet['pattern']}\n")
                            report_lines.append(f"  In function:\n{snippet['function_context']}\n")
                            report_lines.append(f"  Matched code: {snippet['matched_code']}\n")
                            report_lines.append("  " + "-"*50 + "\n")
            else:
                report_lines.append("OK! No suspicious code patterns detected\n")

        # analysis = utils.analyze_token_contract_with_snippets(contract_info['source_code'],pbar=pbar) if contract_info.get('source_code')!= None else None

        # report_lines.append("\nCode Analysis Findings:\n")
        # if analysis != None:
        #     for category, data in analysis.items():
        #         if data['found']:
        #             report_lines.append(f"WARNING: {category.replace('_', ' ').title()}\n")
        #             for snippet in data['snippets']:
        #                 report_lines.append(f"  Code Snippet:\n{snippet}\n\n")
        
        results['analyses']['contract'] = {
            "contract_name": contract_info.get('contract_name', None),
            "compiler_version": contract_info.get('compiler_version', None),
            "license_type": contract_info.get('license_type', None),
            "implementation": contract_info.get('implementation', None),
            "source_code": contract_info.get('source_code', None),
            "abi": contract_info.get('abi', None),
            'verified': contract_info.get('verified', False),
            'owner': owner,
            'creator': creator,
            'is_hidden_owner': False if owner else True,
            'is_proxy': contract_info.get('is_proxy', False),
            'is_sellable': sellable,
            'is_hardcoded_owner': hardcoded,
            'code_analysis': analysis if contract_info.get('source_code') else {
                'total_matches' : 0,
                'patterns_found' : {}
            }
        }
        if pbar:
            pbar.update(6)

    except Exception as e:
        tb = e.__traceback__
        # Walk to the last frame in the traceback (where the error actually happened)
        while tb.tb_next:
            tb = tb.tb_next
        func_name = tb.tb_frame.f_code.co_name
        error_msg = f"Exception during contract analysis in {func_name}: {e}"
        results.setdefault('analyses', {}).setdefault('contract', {})['error'] = error_msg
        report_lines.append(f"⚠️ Contract analysis exception in {func_name}: {error_msg}\n")
        if pbar:
            pbar.update(6)
    return results, report_lines
