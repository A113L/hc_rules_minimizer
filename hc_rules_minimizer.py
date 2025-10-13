#!/usr/bin/env python3
'''
The script is used to process debugged hashcat rules in mode = 1.
It now includes a FUNCTIONAL REDUNDANCY filter based on the provided RuleEngine 
logic to achieve deeper minimization, with corrected logic for statistical filtering.
'''
import sys
import os
import re
from collections import Counter
from typing import List, Tuple, Dict, Callable

# ==============================================================================
# A. RULEENGINE SIMULATOR LOGIC
# ==============================================================================

# Functions for RuleEngine
def i36(string):
    '''Shorter way of converting base 36 string to integer'''
    return int(string, 36)

def rule_regex_gen():
    ''''Generates regex to parse rules'''
    __rules__ = [
        ':', 'l', 'u', 'c', 'C', 't', r'T\w', 'r', 'd', r'p\w', 'f', '{',
        '}', '$.', '^.', '[', ']', r'D\w', r'x\w\w', r'O\w\w', r'i\w.',
        r'o\w.', r"'\w", 's..', '@.', r'z\w', r'Z\w', 'q',
        ]
    __rules__ += [r'X\w\w\w', '4', '6', 'M']
    for i, func in enumerate(__rules__):
        __rules__[i] = func[0]+func[1:].replace(r'\w', '[a-zA-Z0-9]')
    ruleregex = '|'.join(['%s%s' % (re.escape(a[0]), a[1:]) for a in __rules__])
    return re.compile(ruleregex)
__ruleregex__ = rule_regex_gen()

FUNCTS: Dict[str, Callable] = {}
FUNCTS[':'] = lambda x, i: x
FUNCTS['l'] = lambda x, i: x.lower()
FUNCTS['u'] = lambda x, i: x.upper()
FUNCTS['c'] = lambda x, i: x.capitalize()
FUNCTS['C'] = lambda x, i: x.capitalize().swapcase()
FUNCTS['t'] = lambda x, i: x.swapcase()
def T(x, i):
    number = i36(i)
    if number >= len(x): return x # Guard against IndexError
    return ''.join((x[:number], x[number].swapcase(), x[number + 1:]))
FUNCTS['T'] = T
FUNCTS['r'] = lambda x, i: x[::-1]
FUNCTS['d'] = lambda x, i: x+x
FUNCTS['p'] = lambda x, i: x*(i36(i)+1)
FUNCTS['f'] = lambda x, i: x+x[::-1]
FUNCTS['{'] = lambda x, i: x[1:]+x[0] if x else x # Guard against empty string
FUNCTS['}'] = lambda x, i: x[-1]+x[:-1] if x else x # Guard against empty string
FUNCTS['$'] = lambda x, i: x+i
FUNCTS['^'] = lambda x, i: i+x
FUNCTS['['] = lambda x, i: x[1:]
FUNCTS[']'] = lambda x, i: x[:-1]
def D(x, i):
    idx = i36(i)
    if idx >= len(x): return x
    return x[:idx]+x[idx+1:]
FUNCTS['D'] = D
def x(x, i):
    start = i36(i[0])
    end = i36(i[1])
    # Guard against invalid slice indices
    if start < 0 or end < 0 or start > len(x) or end > len(x) or start > end: return "" 
    return x[start:end]
FUNCTS['x'] = x
def O(x, i):
    start = i36(i[0])
    end = i36(i[1])
    # Guard against invalid slice indices
    if start < 0 or end < 0 or start > len(x) or end > len(x): return x
    if start > end: return x
    return x[:start]+x[end+1:]
FUNCTS['O'] = O
def i(x, i):
    pos = i36(i[0])
    char = i[1]
    if pos > len(x): pos = len(x)
    return x[:pos]+char+x[pos:]
FUNCTS['i'] = i
def o(x, i):
    pos = i36(i[0])
    char = i[1]
    if pos >= len(x): return x
    return x[:pos]+char+x[pos+1:]
FUNCTS['o'] = o
FUNCTS["'"] = lambda x, i: x[:i36(i)]
FUNCTS['s'] = lambda x, i: x.replace(i[0], i[1])
FUNCTS['@'] = lambda x, i: x.replace(i, '')
def z(x, i):
    num = i36(i)
    if x: return x[0]*num+x
    return ''
FUNCTS['z'] = z
def Z(x, i):
    num = i36(i)
    if x: return x+x[-1]*num
    return ''
FUNCTS['Z'] = Z
FUNCTS['q'] = lambda x, i: ''.join([a*2 for a in x])

__memorized__ = ['']


def extract_memory(string, args):
    '''Insert section of stored string into current string'''
    if not __memorized__[0]: return string # Handle empty memory
    try:
        pos, length, i = map(i36, args)
        string = list(string)
        # Ensure indices are within bounds
        mem_segment = __memorized__[0][pos:pos+length]
        
        string.insert(i, mem_segment)
        return ''.join(string)
    except Exception:
        # Catch any errors from out-of-bounds access or bad parsing
        return ''.join(string)
FUNCTS['X'] = extract_memory
FUNCTS['4'] = lambda x, i: x+__memorized__[0]
FUNCTS['6'] = lambda x, i: __memorized__[0]+x


def memorize(string, _):
    ''''Store current string in memory'''
    __memorized__[0] = string
    return string
FUNCTS['M'] = memorize


class RuleEngine(object):
    ''' Simplified Rule Engine for functional simulation '''
    def __init__(self, rules: List[str]):
        # Parse rules once during initialization
        self.rules = tuple(map(__ruleregex__.findall, rules))

    def apply(self, string: str) -> str:
        ''' Apply all rules to a single string and yield the results '''
        for rule_functions in self.rules:
            word = string
            # IMPORTANT: Memory must be reset for each new base string!
            __memorized__[0] = ''
            
            for function in rule_functions:
                try:
                    # function[0] is the command, function[1:] is the argument
                    word = FUNCTS[function[0]](word, function[1:])
                except Exception:
                    # Catch IndexError, ValueError, etc., which often happen with 
                    # out-of-bounds Hashcat rules.
                    pass
            # We only care about the final result for this implementation
            return word 
        return string # Fallback if rules is empty

# ==============================================================================
# B. SCRIPT LOGIC WITH REDUNDANCY FILTER
# ==============================================================================

# Global Test Vector for functional comparison
TEST_VECTOR = ["Password", "123456", "ADMIN", "1aB"]

def generate_functional_signatures(all_data: List[str]) -> List[Tuple[str, int]]:
    """
    Generates a functional signature for each unique rule based on the TEST_VECTOR.
    Returns a sorted list of (most_frequent_rule_text, total_count_for_this_signature).
    """
    
    rule_counts: Counter = Counter(all_data)
    unique_rules_with_counts = rule_counts.most_common()
    
    signature_map: Dict[str, List[Tuple[str, int]]] = {}

    print(f"\n[+] Generating functional signatures using test vector: {TEST_VECTOR}")

    # 1. Iterate and simulate each unique rule
    for rule_text, count in unique_rules_with_counts:
        # Temporarily use RuleEngine for a single rule
        engine = RuleEngine([rule_text])
        
        signature_parts: List[str] = []
        
        # Apply the rule to the test vector
        for test_word in TEST_VECTOR:
            result = engine.apply(test_word)
            signature_parts.append(result)

        # Create the unique signature string
        signature = '|'.join(signature_parts)
        
        # 2. Group rules by signature
        if signature not in signature_map:
            signature_map[signature] = []
        
        # Store (rule_text, count) for later selection
        signature_map[signature].append((rule_text, count))

    # 3. Select the best rule for each unique signature (the one with the highest count)
    final_best_rules_list: List[Tuple[str, int]] = []
    
    for signature, rules_list in signature_map.items():
        # Sort rules within the group by count (descending)
        rules_list.sort(key=lambda x: x[1], reverse=True)
        
        # The first element is the most frequent rule for this signature
        best_rule_text, _ = rules_list[0]
        
        # Calculate the total count (sum of all redundant rules)
        total_count = sum(count for _, count in rules_list)
        
        final_best_rules_list.append((best_rule_text, total_count))
        
    # 4. Sort the final list by total count (most valuable signatures first)
    final_best_rules_list.sort(key=lambda x: x[1], reverse=True)

    return final_best_rules_list

def read_file_data(input_filepath: str) -> List[str]:
    # ... (read_file_data remains unchanged)
    if not os.path.exists(input_filepath):
        print(f"Error: Input file '{input_filepath}' does not exist.")
        return []
    
    print(f"[+] Reading file: {input_filepath}")
    
    try:
        # Using 'latin-1' to handle non-UTF-8 bytes
        with open(input_filepath, 'r', encoding='latin-1') as f:
            # Read lines, removing trailing whitespace (e.g., '\n')
            data = [line.strip() for line in f if line.strip()]
            return data
    except IOError as e:
        print(f"[-] File read error for {input_filepath}: {e}")
        return []

def process_multiple_files(input_files: List[str]):
    # --- 1. Reading and Combining Data ---
    all_data: List[str] = []
    print("\n" + "="*60)
    print("STARTING MULTI-FILE PROCESSING")
    print("="*60)
    
    for input_file in input_files:
        file_data = read_file_data(input_file)
        if file_data:
            all_data.extend(file_data)

    if not all_data:
        print("\nNo valid data found across all files. Exiting.")
        return

    total_lines = len(all_data)
    print(f"\n[+] Total lines read across all files: {total_lines:,}")

    # --- 2. Counting and Sorting (Textual Consolidation) ---
    occurrence_counts: Counter = Counter(all_data)
    # The default data list is sorted by count (textual count)
    sorted_data_textual: List[Tuple[str, int]] = occurrence_counts.most_common()
    
    unique_count_textual = len(sorted_data_textual)
    sorted_data = sorted_data_textual # Start with textual data
    
    # Textual Redundancy Stats
    if total_lines > 0:
        unique_percentage = (unique_count_textual / total_lines) * 100
        redundant_lines = total_lines - unique_count_textual
        redundant_percentage = (redundant_lines / total_lines) * 100
    else:
        unique_percentage = 0.0
        redundant_lines = 0
        redundant_percentage = 0.0

    print(f"The consolidated dataset contains {unique_count_textual:,} TEXTUALLY unique entries.")
    print(f"[STAT] Unique entries are {unique_percentage:.2f}% of the total lines read.")
    print(f"[STAT] Redundant lines (duplicates) removed: {redundant_lines:,} ({redundant_percentage:.2f}%)")
    
    # --- 3. User Input for Filtering Mode (Combined Logic) ---
    
    min_count_threshold: int = 1
    max_rule_limit: int = unique_count_textual
    unique_count = unique_count_textual
    mode_choice_1 = ''
    mode_choice_2 = ''

    print("\n" + "-"*60)
    print("RULE FILTERING: Choose Mode")
    print(" (1) Filter by MINIMUM OCCURRENCE (e.g., must appear 100 times)")
    print(" (2) Filter by MAXIMUM NUMBER OF RULES (e.g., save top 50000 rules)")
    print(" (3) Filter by FUNCTIONAL REDUNDANCY (Logic Minimization)")
    print(" (0/Enter) Save ALL unique rules")
    print("-"*60)
    
    while True:
        mode_choice_1 = input("Enter mode choice (1, 2, 3, 0/Enter): ").strip()
        
        if mode_choice_1 in ['', '0', '1', '2', '3']:
            break
        else:
            print("[-] Invalid choice. Please enter 1, 2, 3, 0, or press Enter.")
            
    
    # --- LOGIC MINIMIZATION EXECUTION (MODE 3) ---
    if mode_choice_1 == '3':
        
        # Generate and consolidate based on signature
        sorted_data_functional = generate_functional_signatures(all_data)
        
        # Set the functional data as the primary data source for subsequent steps
        sorted_data = sorted_data_functional
        unique_count = len(sorted_data)
        
        print(f"\n[MINIMIZATION] Logic minimization reduced unique count from {unique_count_textual:,} to {unique_count:,} functional rules.")

        # Re-enter prompt logic for further statistical pruning
        print("\n" + "-"*60)
        print(f"FUNCTIONAL MINIMIZATION APPLIED. New unique count: {unique_count:,}")
        print("Choose further statistical filtering:")
        print(" (1) Filter by MINIMUM TOTAL OCCURRENCE (of the functional group)")
        print(" (2) Filter by MAXIMUM NUMBER OF FUNCTIONAL RULES")
        print(" (0/Enter) Save ALL functional rules")
        print("-"*60)
        
        while True:
            mode_choice_2 = input("Enter mode choice (1, 2, 0/Enter): ").strip()
            if mode_choice_2 in ['', '0', '1', '2']:
                break
            else:
                print("[-] Invalid choice. Please enter 1, 2, 0, or press Enter.")

        if mode_choice_2 in ['', '0']:
            pass # Use defaults
        elif mode_choice_2 == '1':
            mode_choice_1 = '1' # Reroute to MIN_COUNT logic below
        elif mode_choice_2 == '2':
            mode_choice_1 = '2' # Reroute to MAX_COUNT logic below

    
    # --- Execute MIN_COUNT or MAX_COUNT Logic ---

    # Set initial max limit for subsequent filtering based on the currently selected data set
    max_rule_limit = unique_count

    if mode_choice_1 in ['', '0']:
        min_count_threshold = 1
        max_rule_limit = unique_count
    
    if mode_choice_1 == '1':
        # Case 1: Filter by MINIMUM OCCURRENCE COUNT
        max_count = sorted_data[0][1] if sorted_data else 0
        suggested_threshold = max(1, total_lines // 1000)
        
        while True:
            limit_input = input(f"[MODE 1] Enter the MINIMUM OCCURRENCE count (Max: {max_count:,}, Suggested: {suggested_threshold:,}, Min: 1): ").strip()

            try:
                min_count_threshold = int(limit_input)
                if min_count_threshold >= 1:
                    max_rule_limit = unique_count
                    print(f"[+] Selected MIN_COUNT threshold: {min_count_threshold:,}.")
                    break
                else:
                    print(f"[-] The minimum count must be 1 or higher.")
            except ValueError:
                print("[-] Invalid format. Please enter an integer.")

    elif mode_choice_1 == '2':
        # Case 2: Filter by MAXIMUM NUMBER OF RULES (Statistical Pruning)
        while True:
            limit_input = input(f"[MODE 2] Enter the MAXIMUM number of rules to save (1 to {unique_count:,}): ").strip()

            try:
                max_rule_limit = int(limit_input)
                if 1 <= max_rule_limit <= unique_count:
                    min_count_threshold = 1
                    print(f"[+] Selected MAX_COUNT limit (Statistical Pruning): {max_rule_limit:,}.")
                    break
                else:
                    print(f"[-] The number must be between 1 and {unique_count:,}.")
            except ValueError:
                print("[-] Invalid format. Please enter an integer.")

    # 5. Applying the filter based on the chosen mode
    # CORRECTED: Store the entire (item, count) tuple, not just the item!
    data_after_min_count_filter = []
    
    initial_unique_count = unique_count # Use the count of the data set being filtered

    for item, count in sorted_data:
        if count >= min_count_threshold:
            data_after_min_count_filter.append((item, count)) # FIXED HERE
        else:
            break

    # Apply MAX_COUNT limit (Statistical Pruning)
    final_data_to_write = data_after_min_count_filter[:max_rule_limit]
    final_write_count = len(final_data_to_write)
    removed_count = initial_unique_count - final_write_count
    
    print(f"\n[RESULT] Final number of rules to be saved: {final_write_count:,}")
    if removed_count > 0:
        print(f"[RESULT] {removed_count:,} unique rules were removed from the initial set of {initial_unique_count:,}.")
    
    # 6. Generating the output file name
    first_basename = os.path.basename(os.path.splitext(input_files[0])[0])
    
    # Logic for file naming
    filter_str = f"COUNT_{final_write_count}"
    if mode_choice_1 == '3' and mode_choice_2 == '2':
        filter_str = f"F_TOP_{max_rule_limit}"
    elif mode_choice_1 == '3' and mode_choice_2 == '1':
        filter_str = f"F_MIN_{min_count_threshold}"
    elif mode_choice_1 == '3':
        filter_str = f"FUNCTIONAL_{final_write_count}"
    elif mode_choice_1 == '2':
        filter_str = f"TOP_{max_rule_limit}"
    elif mode_choice_1 == '1':
        filter_str = f"MIN_{min_count_threshold}"
        
    output_filepath = f"{first_basename}_CONSOLIDATED_{filter_str}.rule"
    
    input_dir = os.path.dirname(input_files[0])
    if input_dir:
        output_filepath = os.path.join(input_dir, output_filepath)

    # 7. Saving the data to the new file (ONLY the entries)
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            print(f"\nSaving filtered consolidated data to: {output_filepath}")

            # Now this loop works correctly because final_data_to_write contains (item, count) tuples
            for item, _ in final_data_to_write:
                f.write(f"{item}\n")

            print(f"Successfully saved {final_write_count:,} filtered entries.")
            print("\n" + "="*60)
            print("PROCESSING COMPLETE")
            print("="*60)
            
    except IOError as e:
        print(f"File write error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 debugr.py <input_file_path_1> [input_file_path_2 ...]")
        sys.exit(1)
    else:
        input_files = sys.argv[1:]
        print(f"Found {len(input_files)} file(s) to process.")
        
        process_multiple_files(input_files)
