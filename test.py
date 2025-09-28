import wrappers,config,utils

def find_files_with_error(folder_path):
    def contains_error_key(obj, filename, path=""):
        found = False

        if isinstance(obj, dict):
            for key, value in obj.items():
                new_path = f"{path}.{key}" if path else key
                if key.lower() == "error":
                    if value != "Liquidity pool info could not be retrieved.":
                        print(f"[{filename}] Found error at '{new_path}': {value}")
                        found = True
                if contains_error_key(value, filename, new_path):
                    found = True

        elif isinstance(obj, list):
            for index, item in enumerate(obj):
                new_path = f"{path}[{index}]"
                if contains_error_key(item, filename, new_path):
                    found = True

        return found

    error_files = []

    for filename in config.os.listdir(folder_path):
        if not filename.endswith(".json"):
            continue

        file_path = config.os.path.join(folder_path, filename)

        try:
            with open(file_path, 'r') as f:
                data = config.json.load(f)
        except config.json.JSONDecodeError:
            continue  # Skip malformed JSON

        if contains_error_key(data, filename):
            error_files.append(filename)

    return error_files

import json
from collections import defaultdict
from typing import Dict, Tuple

def load_slippage_data(txt_path: str) -> Dict[Tuple[str, str], dict]:
    slippage_map = {}
    with open(txt_path, 'r') as f:
        lines = f.readlines()

    i = 0
    while i < len(lines):
        key_line = lines[i].strip()
        i += 1

        # Skip empty lines
        if not key_line:
            continue

        # Extract address and chain
        try:
            addr_part, chain_part = key_line.split(":")
            address = addr_part.strip().strip('"').lower()
            chain = chain_part.strip().strip('"').lower()
        except Exception as e:
            raise ValueError(f"Failed to parse key line: {key_line}\nError: {e}")

        # Now parse the JSON block starting at the next line
        json_lines = []
        brace_count = 0
        while i < len(lines):
            line = lines[i]
            json_lines.append(line)
            brace_count += line.count("{") - line.count("}")
            i += 1
            if brace_count == 0:
                break

        json_str = ''.join(json_lines).strip()
        try:
            slippage_data = json.loads(json_str)
            slippage_map[(address, chain)] = slippage_data
        except Exception as e:
            raise ValueError(f"Failed to parse JSON value: {json_str}\nError: {e}")

    return slippage_map


from pathlib import Path
import json
from collections import OrderedDict

def process_folder(json_folder_path: str, slippage_txt_path: str):
    json_folder = Path(json_folder_path)
    modified_folder = json_folder / "modified"
    modified_folder.mkdir(exist_ok=True)

    # ✅ Load slippage data with updated format
    slippage_map = load_slippage_data(slippage_txt_path)

    for jf in json_folder.glob("*.json"):
        with open(jf, 'r') as f:
            content = json.load(f, object_pairs_hook=OrderedDict)

        token_addr = content.get("token_address", "").lower()
        chain = content.get("chain", "").lower()
        key = (token_addr, chain)

        if key not in slippage_map:
            print(f"⚠️  No slippage data for {token_addr} / {chain}, skipping {jf.name}")
            continue

        slip = slippage_map[key]

        percent_slippages = slip.get("slippages_by_percent", {}).get("slippage_percents", [])
        fixed_slippages = slip.get("slippages_by_fixed_input", {}).get("slippage_percents", [])
        first_abnorm_pct = slip.get("slippages_by_percent", {}).get("first_abnormal_slippage")
        first_abnorm_fixed = slip.get("slippages_by_fixed_input", {}).get("first_abnormal_slippage")
        overall_susp = slip.get("is_suspicious", False)

        percent_suspicious = first_abnorm_pct is not None
        fixed_suspicious = first_abnorm_fixed is not None

        new_liq_fields = OrderedDict([
            ("is_suspicious", overall_susp),
            ("first_abnormal_slippage_percent", first_abnorm_pct if percent_suspicious else None),
            ("first_abnormal_slippage_fixed", first_abnorm_fixed if fixed_suspicious else None),
            ("slippage_by_percent", max(percent_slippages) if percent_slippages else 0.0),
            ("slippage_by_fixed_input", max(fixed_slippages) if fixed_slippages else 0.0),
        ])

        analyses = content.get("analyses")
        if analyses is None:
            print(f"❌ {jf.name} missing 'analyses'. Skipping.")
            continue
        liquidity = analyses.get("liquidity")
        if liquidity is None:
            print(f"❌ {jf.name} missing 'analyses.liquidity'. Skipping.")
            continue

        new_liq = OrderedDict()
        for k, v in liquidity.items():
            if k == "slippage_is_suspicious":
                new_liq.update(new_liq_fields)
            elif k in ("first_abnormal_slippage_percent", "first_abnormal_slippage_fixed"):
                continue
            else:
                new_liq[k] = v

        # Ensure all new fields are present
        for k, v in new_liq_fields.items():
            new_liq.setdefault(k, v)

        content["analyses"]["liquidity"] = new_liq

        out_path = modified_folder / jf.name
        with open(out_path, 'w') as f:
            json.dump(content, f, indent=4)

        print(f"✅ Modified: {out_path.name}")

    print("🎉 Done processing all files.")

from pathlib import Path
from collections import OrderedDict
import json

def test_single_file(json_file_path: str, slippage_txt_path: str):
    json_path = Path(json_file_path)
    modified_path = json_path.parent / "modified"
    modified_path.mkdir(exist_ok=True)

    slippage_map = load_slippage_data(slippage_txt_path)

    with open(json_path, 'r') as f:
        content = json.load(f, object_pairs_hook=OrderedDict)

    token_addr = content.get("token_address", "").lower()
    chain = content.get("chain", "").lower()
    key = (token_addr, chain)

    if key not in slippage_map:
        print(f"❌ No slippage data found for token: {token_addr}, chain: {chain}")
        return

    slip = slippage_map[key]
    percent_slippages = slip.get("slippages_by_percent", {}).get("slippage_percents", [])
    fixed_slippages = slip.get("slippages_by_fixed_input", {}).get("slippage_percents", [])
    first_abnorm_pct = slip.get("slippages_by_percent", {}).get("first_abnormal_slippage")
    first_abnorm_fixed = slip.get("slippages_by_fixed_input", {}).get("first_abnormal_slippage")
    overall_susp = slip.get("is_suspicious", False)

    new_liq_fields = OrderedDict([
        ("is_suspicious", overall_susp),
        ("first_abnormal_slippage_percent", first_abnorm_pct),
        ("first_abnormal_slippage_fixed", first_abnorm_fixed),
        ("slippage_by_percent", max(percent_slippages) if percent_slippages else 0.0),
        ("slippage_by_fixed_input", max(fixed_slippages) if fixed_slippages else 0.0),
    ])

    analyses = content.get("analyses")
    if not analyses or "liquidity" not in analyses:
        print(f"❌ 'analyses.liquidity' not found in JSON.")
        return

    old_liquidity = analyses["liquidity"]
    new_liquidity = OrderedDict()

    for k, v in old_liquidity.items():
        if k == "slippage_is_suspicious":
            new_liquidity.update(new_liq_fields)
        elif k in ("first_abnormal_slippage_percent", "first_abnormal_slippage_fixed"):
            continue
        else:
            new_liquidity[k] = v

    for k, v in new_liq_fields.items():
        new_liquidity.setdefault(k, v)

    content["analyses"]["liquidity"] = new_liquidity

    output_file = modified_path / json_path.name
    with open(output_file, 'w') as f:
        json.dump(content, f, indent=4)

    print(f"✅ Modified file saved to: {output_file}")


def main():
    test_single_file("C:/Users/Famiglia/Desktop/Amedeo/TESI/Progetto_tesi/thesis/goodtokens_data_collection/new/token_analysis_0x2047ab30_full_20250923_153719.json","C:/Users/Famiglia/Desktop/Amedeo/TESI/Progetto_tesi/thesis/GOOD_slippage_log.txt")
    return
    process_folder("/path/to/json_files", "/path/to/slippage_data.txt")
    return

if __name__ == '__main__': 
    main()
