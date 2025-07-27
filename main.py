import wrappers,config,utils

"""----------------------------------------"""
def process_csv(input_csv, output_csv, process_first_n=10):
    # Open and read the input CSV file
    with open(input_csv, newline='', encoding='utf-8') as infile:
        reader = config.csv.DictReader(infile)
        # Prepare output data structure
        output_data = []
        line_count = 0
        # Iterate through each row in the CSV
        for row in reader:
            if line_count >= process_first_n:
                break
            token_address = row['token_address']
            blockchain = row['blockchain']
            
            # Run the analysis for each token address
            analysis_result = analyze_token(token_address, blockchain)
            
            # Extract relevant data from the JSON result, using .get() to handle missing keys safely
            analysis = analysis_result['analyses']
            row_data = {
                'token_address': token_address,
                'contract_info': config.json.dumps(analysis.get('contract', {}).get('info', "")),
                'contract_verified': analysis.get('contract', {}).get('verified', ""),
                'contract_owner': analysis.get('contract', {}).get('owner', ""),
                'holders_total': analysis.get('holders', {}).get('total_holders', ""),
                'holders_compliant': analysis.get('holders', {}).get('summary', {}).get('compliant', ""),
                'liquidity_error': analysis.get('liquidity', {}).get('error', ""),
                'security_warnings': config.json.dumps(analysis.get('security', {}).get('warnings', "")),
                'security_suspicious_urls': config.json.dumps(analysis.get('security', {}).get('suspicious_urls', "")),
                'security_suspicious_addresses': config.json.dumps(analysis.get('security', {}).get('suspicious_addresses', "")),
                'lifecycle_creation_date': analysis.get('lifecycle', {}).get('token_creation_date', ""),
                'lifecycle_inactive_days': analysis.get('lifecycle', {}).get('inactive_days', "")
            }
            output_data.append(row_data)
            line_count +=1
        # Write the output data to the new CSV file
        fieldnames = [
            'token_address', 'contract_info', 'contract_verified', 'contract_owner',
            'holders_total', 'holders_compliant', 'liquidity_error', 
            'security_warnings', 'security_suspicious_urls', 'security_suspicious_addresses',
            'lifecycle_creation_date', 'lifecycle_inactive_days'
        ]
        
        with open(output_csv, mode='w', newline='', encoding='utf-8') as outfile:
            writer = config.csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            for data in output_data:
                writer.writerow(data)

def analyze_token(token_address: str, chain: str, analysis_types: list = None) -> dict:

    print(f"\nStarting Analysis of token {token_address} on chain {chain} of types {"full" if analysis_types == None else analysis_types}!")
    if analysis_types is None:
        analysis_types = ['contract', 'holder', 'liquidity', 'security', 'lifecycle']
        filename_suffix = "full"
    else:
        filename_suffix = "_".join(analysis_types) if len(analysis_types) > 1 else analysis_types[0]

    try:
        if chain == 'bsc':
            web3 = config.Web3(config.Web3.HTTPProvider(config.RPC_BSC))
        elif chain == 'eth':
            web3 = config.Web3(config.Web3.HTTPProvider(config.RPC_ETH))
        else:
            web3 = None
    except Exception as e:
        raise ConnectionError(f"❌ Failed to connect to {chain} RPC: {e}")

    results = {
        'token_address': token_address,
        'chain': chain,
        'token_name': utils.get_token_name(token_address, chain),
        'analyses': {},
        'errors': []
    }

    report_lines = []
    report_lines.append(f"Token Analysis Report\n{'='*50}\n")
    report_lines.append(f"Token: {results['token_name']} ({token_address})\n")
    report_lines.append(f"Chain: {chain.upper()}\n")

    steps_per_analysis = {
        'contract': 6,
        'holder': 12,
        'liquidity': 5,
        'security': 5,
        'lifecycle': 4
    }
    total_steps = sum(steps_per_analysis.get(atype, 0) for atype in analysis_types)

    with config.tqdm(total=total_steps, desc="Analyzing Token") as pbar:
        for atype in analysis_types:
            try:
                if atype == 'contract':
                    results, report_lines = wrappers.contract_analysis(token_address, chain, results, report_lines, pbar=pbar)
                elif atype == 'holder':
                    results, report_lines = wrappers.holder_analysis(token_address, chain, results, report_lines, web3, pbar=pbar)
                elif atype == 'liquidity':
                    results, report_lines = wrappers.liquidity_analysis(token_address, chain, results, report_lines, web3, pbar=pbar)
                elif atype == 'security':
                    results, report_lines = wrappers.security_analysis(token_address, chain, results, report_lines, pbar=pbar)
                elif atype == 'lifecycle':
                    results, report_lines = wrappers.lifecycle_analysis(token_address, chain, results, report_lines, pbar=pbar)
                else:
                    # Unknown analysis type - just skip or log
                    error_msg = f"Unknown analysis type requested: {atype}"
                    results['errors'].append(error_msg)
                    report_lines.append(f"⚠️ {error_msg}\n")
            except Exception as e:
                error_msg = f"Exception during {atype} analysis: {e}"
                results['errors'].append(error_msg)
                report_lines.append(f"⚠️ {error_msg}\n")

    report = ''.join(report_lines)
    timestamp = config.datetime.now().strftime('%Y%m%d_%H%M%S')
    config.os.makedirs('test', exist_ok=True)
    report_filename = config.os.path.join('test', f"token_analysis_{token_address[:8]}_{filename_suffix}_{timestamp}.txt")
    json_filename = config.os.path.join('test', f"token_analysis_{token_address[:8]}_{filename_suffix}_{timestamp}.json")
    with open(report_filename, 'w', encoding='utf-8') as f:
        f.write(report)

    with open(json_filename, 'w') as f:
        config.json.dump(results, f, indent=4)

    print(f"\n✅ Analysis complete!")
    print(f"📝 Report saved to: {report_filename}")
    print(f"📊 JSON data saved to: {json_filename}")

    return results

def main():
    start = config.time.perf_counter()
    analyze_token("0x7C5fC45348cbf7dadADd74adBF882505903F0F1b",'bsc')
    end = config.time.perf_counter()
    print(f"Execution time: {end - start:.4f} seconds")
    return 
    start = config.time.perf_counter()
    input_csv = '/home/amedeo/Desktop/code_tests/data/token_list.csv'
    output_csv = '/home/amedeo/Desktop/code_tests/test/output_analysis.csv'
    process_csv(input_csv, output_csv)
    end = config.time.perf_counter()
    return
    start = config.time.perf_counter()
    analyze_token("0xeBdaD1Ae0580fdD4215796D4c8308199D41BF565",'bsc')
    end = config.time.perf_counter()
    print(f"Execution time: {end - start:.4f} seconds")
    return

if __name__ == '__main__':
    main()
