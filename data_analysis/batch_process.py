import pandas as pd
import json
import os
from pathlib import Path
import glob

def find_json_files(base_path="."):
    """
    Find all JSON files recursively in the given path
    """
    json_files = []
    
    # Method 1: Look for test_data_analysis folder
    test_data_path = Path(base_path) / "test_data_analysis"
    if test_data_path.exists():
        json_files.extend(list(test_data_path.glob("*.json")))
        print(f"Found {len(json_files)} JSON files in test_data_analysis folder")
    
    # Method 2: Look for token_analysis JSON files in current directory
    current_dir_files = list(Path(base_path).glob("token_analysis_*.json"))
    if current_dir_files:
        json_files.extend(current_dir_files)
        print(f"Found {len(current_dir_files)} token_analysis JSON files in current directory")
    
    # Method 3: Search recursively for all token_analysis JSON files
    if not json_files:
        recursive_files = list(Path(base_path).rglob("token_analysis_*.json"))
        json_files.extend(recursive_files)
        print(f"Found {len(recursive_files)} token_analysis JSON files recursively")
    
    return json_files

def process_token_analysis_json(file_path):
    """
    Process a single token analysis JSON file and return 5 dataframes
    """
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None, None, None, None, None, None, None
    
    # 1. Contract DataFrame
    contract = data.get('analyses', {}).get('contract', {})
    code_analysis = contract.get('code_analysis', {})
    if code_analysis == {} or code_analysis == None:
        total_snippets = 0
    else:
        total_snippets = sum(section.get('snippets_number', 0) for section in code_analysis.values())
    selected_keys = ['compiler_version', 'license_type', 'implementation','source_code','abi','code_analysis']

    derived_columns = {
        'has_source_code': True if contract.get("source_code") else False,
        'has_abi': True if contract.get("abi") else False,
        'total_snippets': total_snippets,
        'mint_function_detected_number': code_analysis.get('mint_function_detected',{}).get("snippets_number",0) if code_analysis else 0,
        'ownership_renounced_number': code_analysis.get('ownership_renounced',{}).get("snippets_number",0) if code_analysis else 0,
        'is_honeypot_suspected_number': code_analysis.get('is_honeypot_suspected',{}).get("snippets_number",0) if code_analysis else 0,
        'delayed_trading_detected_number': code_analysis.get('delayed_trading_detected',{}).get("snippets_number",0) if code_analysis else 0,
        'transfer_cooldown_detected_number': code_analysis.get('transfer_cooldown_detected',{}).get("snippets_number",0) if code_analysis else 0,
        'high_tax_detected_number': code_analysis.get('high_tax_detected',{}).get("snippets_number",0) if code_analysis else 0,
        'blacklist_or_whitelist_detected_number': code_analysis.get('blacklist_or_whitelist_detected',{}).get("snippets_number",0) if code_analysis else 0,
        'trading_disabled_possible_number': code_analysis.get('trading_disabled_possible',{}).get("snippets_number",0) if code_analysis else 0,
        'other_suspicious_detected_number': code_analysis.get('other_suspicious_detected',{}).get("snippets_number",0) if code_analysis else 0,
    }
    
    contract_data = {
        'token_address': data['token_address'],
        'chain': data['chain'],
        'token_name': data['token_name'],
        **{k: v for k, v in contract.items() if k not in selected_keys},
        **derived_columns
    }
    contract_df = pd.DataFrame([contract_data])
    
    # 2. Holders DataFrame (excluding holders_list)
    selected_keys = ['holders_list','top_10_holders','holders_exceeding_5_percent','owner','creator']
    holders_data = {
        'token_address': data['token_address'],
        'chain': data['chain'],
        'token_name': data['token_name'],
        **{k: v for k, v in data['analyses']['holder'].items() if k not in selected_keys}
    }
    holders_df = pd.DataFrame([holders_data])
    
    # 2.1. Holders List DataFrame (Long Format)
    holders_list_data = []
    if 'holders_list' in data['analyses']['holder'] and data['analyses']['holder']['holders_list']:
        for address, holder_info in data['analyses']['holder']['holders_list'].items():
            row = {
                'token_address': data['token_address'],
                'chain': data['chain'],
                'token_name': data['token_name'],
                'holder_address': address,
                **holder_info
            }
            holders_list_data.append(row)
    else:
        # Add empty row if no holders_list
        row = {
            'token_address': data['token_address'],
            'chain': data['chain'],
            'token_name': data['token_name'],
            'holder_address': None,
            'balance': None,
            'percentage_of_total_supply': None,
            'percentage_of_circulating_supply': None
        }
        holders_list_data.append(row)
    
    if data['analyses']['holder'].get('owner',{}) != None and data['analyses']['holder'].get('owner',{}).get('address','') not in holders_list_data:
        if 'owner' in data['analyses']['holder'] and data['analyses']['holder']['owner']:
            row = {
                'token_address': data['token_address'],
                'chain': data['chain'],
                'token_name': data['token_name'],
                'holder_address': data['analyses']['holder']['owner']['address'],
                'balance': data['analyses']['holder']['owner']['balance'],
                'percentage_of_total_supply': float((data['analyses']['holder']['owner']['balance'] / data['analyses']['holder']['total_supply']) * 100),
                'percentage_of_circulating_supply': data['analyses']['holder']['owner']['percentage_of_supply']
            }
            holders_list_data.append(row)

    if data['analyses']['holder'].get('creator',{}) != None and data['analyses']['holder'].get('creator',{}).get('address','') not in holders_list_data:
        if 'creator' in data['analyses']['holder'] and data['analyses']['holder']['creator']:
            row = {
                'token_address': data['token_address'],
                'chain': data['chain'],
                'token_name': data['token_name'],
                'holder_address': data['analyses']['holder']['creator']['address'],
                'balance': data['analyses']['holder']['creator']['balance'],
                'percentage_of_total_supply': float((data['analyses']['holder']['creator']['balance'] / data['analyses']['holder']['total_supply']) * 100),
                'percentage_of_circulating_supply': data['analyses']['holder']['creator']['percentage_of_supply']
            }
            holders_list_data.append(row)

    holders_list_df = pd.DataFrame(holders_list_data)
    
    # 3. Liquidity DataFrame (excluding lp_holders)
    liquidity_data = {
        'token_address': data['token_address'],
        'chain': data['chain'],
        'token_name': data['token_name'],
        **{k: v for k, v in data['analyses']['liquidity'].items() if k != 'lp_holders'}
    }
    liquidity_df = pd.DataFrame([liquidity_data])
    
    # 3.1. LP Holders DataFrame (Long Format)
    lp_holders_data = []
    if 'lp_holders' in data['analyses']['liquidity'] and data['analyses']['liquidity']['lp_holders']:
        for lp_holder in data['analyses']['liquidity']['lp_holders']:
            row = {
                'token_address': data['token_address'],
                'chain': data['chain'],
                'token_name': data['token_name'],
                **lp_holder
            }
            lp_holders_data.append(row)
    else:
        # Add empty row if no lp_holders
        row = {
            'token_address': data['token_address'],
            'chain': data['chain'],
            'token_name': data['token_name'],
            'address': None,
            'balance': None,
            'is_locked': None,
            'percent': None,
            'tag': None
        }
        lp_holders_data.append(row)
    lp_holders_df = pd.DataFrame(lp_holders_data)
    
    # 4. Security DataFrame
    selected_keys = ['warnings','suspicious_urls','suspicious_addresses','homany_warnings']
    security_data = {
        'token_address': data['token_address'],
        'chain': data['chain'],
        'token_name': data['token_name'],
        **{k: v for k, v in data['analyses']['security'].items() if k not in selected_keys}
    }
    security_df = pd.DataFrame([security_data])
    
    # 5. Lifecycle DataFrame
    lifecycle_data = {
        'token_address': data['token_address'],
        'chain': data['chain'],
        'token_name': data['token_name'],
        **data['analyses']['lifecycle']
    }
    lifecycle_df = pd.DataFrame([lifecycle_data])
    
    return contract_df, holders_df, holders_list_df, liquidity_df, lp_holders_df, security_df, lifecycle_df

def process_all_json_files(base_path="."):
    """
    Process all JSON files and return combined dataframes
    """
    # Find all JSON files
    json_files = find_json_files(base_path)
    
    if not json_files:
        print("No JSON files found!")
        return {}
    
    # Initialize empty lists to store all dataframes
    all_contracts = []
    all_holders = []
    all_holders_list = []
    all_liquidity = []
    all_lp_holders = []
    all_security = []
    all_lifecycle = []
    
    print(f"Processing {len(json_files)} JSON files...")
    
    for i, json_file in enumerate(json_files, 1):
        print(f"Processing {i}/{len(json_files)}: {json_file.name}")
        
        result = process_token_analysis_json(json_file)
        if result is not None:
            contract_df, holders_df, holders_list_df, liquidity_df, lp_holders_df, security_df, lifecycle_df = result
            
            all_contracts.append(contract_df)
            all_holders.append(holders_df)
            all_holders_list.append(holders_list_df)
            all_liquidity.append(liquidity_df)
            all_lp_holders.append(lp_holders_df)
            all_security.append(security_df)
            all_lifecycle.append(lifecycle_df)
    
    # Combine all dataframes
    print("Combining dataframes...")
    
    master_contract_df = pd.concat(all_contracts, ignore_index=True) if all_contracts else pd.DataFrame()
    master_holders_df = pd.concat(all_holders, ignore_index=True) if all_holders else pd.DataFrame()
    master_holders_list_df = pd.concat(all_holders_list, ignore_index=True) if all_holders_list else pd.DataFrame()
    master_liquidity_df = pd.concat(all_liquidity, ignore_index=True) if all_liquidity else pd.DataFrame()
    master_lp_holders_df = pd.concat(all_lp_holders, ignore_index=True) if all_lp_holders else pd.DataFrame()
    master_security_df = pd.concat(all_security, ignore_index=True) if all_security else pd.DataFrame()
    master_lifecycle_df = pd.concat(all_lifecycle, ignore_index=True) if all_lifecycle else pd.DataFrame()
    
    return {
        'contract': master_contract_df,
        'holders': master_holders_df,
        'holders_list': master_holders_list_df,
        'liquidity': master_liquidity_df,
        'lp_holders': master_lp_holders_df,
        'security': master_security_df,
        'lifecycle': master_lifecycle_df
    }

# Usage
if __name__ == "__main__":
    # Process all JSON files
    master_dataframes = process_all_json_files("../data")
    
    if master_dataframes:
        # Access individual dataframes
        contract_df = master_dataframes['contract']
        holders_df = master_dataframes['holders']
        holders_list_df = master_dataframes['holders_list']
        liquidity_df = master_dataframes['liquidity']
        lp_holders_df = master_dataframes['lp_holders']
        security_df = master_dataframes['security']
        lifecycle_df = master_dataframes['lifecycle']
        
        # Print summary
        print("\n" + "="*50)
        print("SUMMARY")
        print("="*50)
        print(f"Contract records: {len(contract_df)}")
        print(f"Holders records: {len(holders_df)}")
        print(f"Holders list records: {len(holders_list_df)}")
        print(f"Liquidity records: {len(liquidity_df)}")
        print(f"LP holders records: {len(lp_holders_df)}")
        print(f"Security records: {len(security_df)}")
        print(f"Lifecycle records: {len(lifecycle_df)}")
        
        # Optional: Save to CSV files
        print("\nSaving to CSV files...")
        contract_df.to_csv("master_contract.csv", index=False)
        holders_df.to_csv("master_holders.csv", index=False)
        holders_list_df.to_csv("master_holders_list.csv", index=False)
        liquidity_df.to_csv("master_liquidity.csv", index=False)
        lp_holders_df.to_csv("master_lp_holders.csv", index=False)
        security_df.to_csv("master_security.csv", index=False)
        lifecycle_df.to_csv("master_lifecycle.csv", index=False)
        print("CSV files saved successfully!")
    else:
        print("No data to process!")
