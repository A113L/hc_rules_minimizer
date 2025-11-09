#!/usr/bin/env python3
'''
The script is used to process debugged hashcat rules from files.
Features:
- Full Hashcat Rule Engine simulation for Functional Minimization (Mode 3).
- Multiprocessing (tqdm) for fast Functional Minimization.
- Optional disk usage for initial consolidation of huge files (--use-disk).
- Statistical Cutoff (Mode 2) and Inverse Mode (Mode 4) for dual-phase attacks.
- Pareto Analysis (Cumulative Value) for suggesting cutoff limits.
- Levenshtein Distance Filtering for Semantic Redundancy Removal, optimized with NumPy (optional).
- NEW: Option to output results to STDOUT for piping (-o / --output-stdout).
'''
import sys
import os
import re
from collections import Counter
from typing import List, Tuple, Dict, Callable, Any
import argparse
import tempfile
import multiprocessing
from tqdm import tqdm

# --- NUMPY IMPLEMENTATION CHECK (NEW) ---
NUMPY_AVAILABLE = False
try:
    import numpy as np
    NUMPY_AVAILABLE = True
    print("[INFO] NumPy found. Using optimized Levenshtein distance calculation.")
except ImportError:
    print("[WARNING] NumPy not found. Falling back to slower pure Python Levenshtein distance calculation.")

# ==============================================================================
# A. RULEENGINE SIMULATOR LOGIC (Hashcat Functions)
# ==============================================================================

# Functions for RuleEngine
def i36(string):
    '''Shorter way of converting base 36 string to integer'''
    return int(string, 36)

# --- FUNCTS DICTIONARY ---
FUNCTS: Dict[str, Callable] = {}
FUNCTS[':'] = lambda x, i: x
FUNCTS['l'] = lambda x, i: x.lower()
FUNCTS['u'] = lambda x, i: x.upper()
FUNCTS['c'] = lambda x, i: x.capitalize()
FUNCTS['C'] = lambda x, i: x.capitalize().swapcase()
FUNCTS['t'] = lambda x, i: x.swapcase()

def T(x, i):
    number = i36(i)
    if number >= len(x): return x
    return ''.join((x[:number], x[number].swapcase(), x[number + 1:]))
FUNCTS['T'] = T

FUNCTS['r'] = lambda x, i: x[::-1]
FUNCTS['d'] = lambda x, i: x+x
FUNCTS['p'] = lambda x, i: x*(i36(i)+1)
FUNCTS['f'] = lambda x, i: x+x[::-1]
FUNCTS['{'] = lambda x, i: x[1:]+x[0] if x else x
FUNCTS['}'] = lambda x, i: x[-1]+x[:-1] if x else x
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
    # Hashcat x functions takes two arguments (start, end)
    start = i36(i[0])
    end = i36(i[1])
    if start < 0 or end < 0 or start > len(x) or end > len(x) or start > end: return "" 
    return x[start:end]
FUNCTS['x'] = x

def O(x, i):
    # Hashcat O functions takes two arguments (start, end)
    start = i36(i[0])
    end = i36(i[1])
    if start < 0 or end < 0 or start > len(x) or end > len(x): return x
    if start > end: return x
    return x[:start]+x[end+1:]
FUNCTS['O'] = O

def i(x, i):
    # Hashcat i functions takes two arguments (pos, char)
    pos = i36(i[0])
    char = i[1]
    if pos > len(x): pos = len(x)
    return x[:pos]+char+x[pos:]
FUNCTS['i'] = i

def o(x, i):
    # Hashcat o functions takes two arguments (pos, char)
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
    if not __memorized__[0]: return string
    try:
        # Note: Your implementation of X uses three arguments, matching hashcat's memory extraction
        pos, length, i = map(i36, args)
        string_list = list(string)
        mem_segment = __memorized__[0][pos:pos+length]
        string_list.insert(i, mem_segment)
        return ''.join(string_list)
    except Exception:
        # Fallback to original string if arguments fail
        return string 
FUNCTS['X'] = extract_memory
FUNCTS['4'] = lambda x, i: x+__memorized__[0]
FUNCTS['6'] = lambda x, i: __memorized__[0]+x

def memorize(string, _):
    ''''Store current string in memory'''
    __memorized__[0] = string
    return string
FUNCTS['M'] = memorize


def rule_regex_gen():
    ''''Generates regex to parse rules'''
    __rules__ = [
        ':', 'l', 'u', 'c', 'C', 't', r'T\w', 'r', 'd', r'p\w', 'f', '{',
        '}', '$.', '^.', '[', ']', r'D\w', r'x\w\w', r'O\w\w', r'i\w.',
        r'o\w.', r"'\w", 's..', '@.', r'z\w', r'Z\w', 'q',
        r'X\w\w\w', '4', '6', 'M'
        ]
    # Build regex, escaping the first character but using raw regex for the arguments
    for i, func in enumerate(__rules__):
        __rules__[i] = re.escape(func[0]) + func[1:].replace(r'\w', '[a-zA-Z0-9]')
    ruleregex = '|'.join(__rules__)
    return re.compile(ruleregex)
__ruleregex__ = rule_regex_gen()


class RuleEngine(object):
    ''' Simplified Rule Engine for functional simulation '''
    def __init__(self, rules: List[str]):
        # Parse all rule strings into a list of lists of function strings
        self.rules = tuple(map(__ruleregex__.findall, rules))

    def apply(self, string: str) -> str:
        ''' 
        Apply all functions in the rule string to a single string and return the result.
        
        CRITICAL FIX: The 'return word' statement was moved outside the inner loop 
        to ensure all functions in a single rule are executed before returning.
        '''
        for rule_functions in self.rules: # self.rules contains one parsed rule (list of functions)
            word = string
            __memorized__[0] = ''
            
            for function in rule_functions: # Iterate over functions in the rule
                try:
                    word = FUNCTS[function[0]](word, function[1:])
                except Exception:
                    pass
            
            # This returns the result after ALL functions in the rule have been applied.
            return word 
        
        return string

# ==============================================================================
# B. CORE LOGIC
# ==============================================================================

# --- LEVENSHTEIN LOGIC (MODIFIED WITH NUMPY) ---

if NUMPY_AVAILABLE:
    def levenshtein_distance(s1: str, s2: str) -> int:
        """
        Calculates the Levenshtein distance between two strings using NumPy for matrix operations.
        """
        if len(s1) > len(s2):
            s1, s2 = s2, s1

        rows = len(s1) + 1
        cols = len(s2) + 1
        
        D = np.zeros((rows, cols), dtype=int)
        D[:, 0] = np.arange(rows)
        D[0, :] = np.arange(cols)

        for j in range(1, cols):
            for i in range(1, rows):
                cost = 0 if s1[i-1] == s2[j-1] else 1
                
                D[i, j] = min(
                    D[i-1, j] + 1,        # Deletion
                    D[i, j-1] + 1,        # Insertion
                    D[i-1, j-1] + cost    # Substitution
                )
                
        return D[rows - 1, cols - 1]

else: # Pure Python Fallback
    def levenshtein_distance(s1: str, s2: str) -> int:
        """
        Calculates the Levenshtein distance using pure Python (slow fallback).
        """
        if len(s1) > len(s2):
            s1, s2 = s2, s1

        distances = list(range(len(s1) + 1))
        
        for i2, c2 in enumerate(s2):
            new_distances = [i2 + 1]
            for i1, c1 in enumerate(s1):
                cost = 0 if c1 == c2 else 1
                
                new_distances.append(min((distances[i1 + 1] + 1, 
                                          new_distances[-1] + 1, 
                                          distances[i1] + cost)))
                                          
            distances = new_distances
        return distances[-1]


def apply_levenshtein_filter(rules_data: List[Tuple[str, int]], max_dist: int) -> List[Tuple[str, int]]:
    """
    Filters a list of rules (rule, count) based on Levenshtein distance.
    The list must be sorted by count (most common first). Only rules too close (<= max_dist) 
    to an already accepted rule are removed, preserving the most common rule in a semantic group.
    """
    if max_dist <= 0:
        return rules_data 
    
    print(f"\n[FILTER] Applying Levenshtein Filter (Max Distance: {max_dist}) to {len(rules_data):,} rules...")
    
    final_rules: List[Tuple[str, int]] = []
    final_rule_strings: List[str] = []
    
    total_rejected = 0

    # This loop MUST be sequential as the acceptance of rule 'A' dictates 
    # whether subsequent rules 'B', 'C', etc., are redundant.
    for rule, count in tqdm(rules_data, desc="Levenshtein filtering"):
        is_redundant = False
        
        for existing_rule in final_rule_strings:
            if levenshtein_distance(rule, existing_rule) <= max_dist:
                is_redundant = True
                total_rejected += 1
                break
        
        if not is_redundant:
            final_rules.append((rule, count))
            final_rule_strings.append(rule)
            
    print(f"[FILTER] Rules rejected by Levenshtein filter: {total_rejected:,}. Final rules: {len(final_rules):,}.")
    return final_rules

# --- Rule Engine Worker and Signature Generation ---
TEST_VECTOR = [
    "Password", "123456", "ADMIN", "1aB", "QWERTY", 
    "longword", "spec!", "!spec", "a", "b", "c", "0123", 
    "xYz!", "TEST", "tEST", "test", "0", "1", "$^", "lorem", "ipsum"
]

def worker_generate_signature(rule_data: Tuple[str, int]) -> Tuple[str, Tuple[str, int]]:
    """Worker function for multiprocessing pool."""
    rule_text, count = rule_data
    # Re-initialize RuleEngine for each rule
    engine = RuleEngine([rule_text])
    signature_parts: List[str] = []
    
    for test_word in TEST_VECTOR:
        result = engine.apply(test_word)
        signature_parts.append(result)

    signature = '|'.join(signature_parts)
    return signature, (rule_text, count)


def generate_functional_signatures(unique_rules_with_counts: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Generates signatures in parallel and consolidates them."""
    
    signature_map: Dict[str, List[Tuple[str, int]]] = {}
    
    print(f"\n[+] Generating functional signatures using test vector (Length: {len(TEST_VECTOR)}): {TEST_VECTOR[:4]}... (Parallel processing activated)")
    
    num_processes = multiprocessing.cpu_count()
    print(f"[MP] Using {num_processes} processes for functional simulation.")

    with multiprocessing.Pool(processes=num_processes) as pool:
        results = list(tqdm(
            pool.imap(worker_generate_signature, unique_rules_with_counts),
            total=len(unique_rules_with_counts),
            desc="Simulating rules",
            unit=" rules"
        ))
    
    for signature, rule_data in results:
        if signature not in signature_map:
            signature_map[signature] = []
        signature_map[signature].append(rule_data)

    final_best_rules_list: List[Tuple[str, int]] = []
    
    for signature, rules_list in signature_map.items():
        # Sort by count (highest first) to pick the most common rule as the representative
        rules_list.sort(key=lambda x: x[1], reverse=True)
        best_rule_text, _ = rules_list[0]
        # Sum all counts to get the total functional value
        total_count = sum(count for _, count in rules_list)
        final_best_rules_list.append((best_rule_text, total_count))
        
    final_best_rules_list.sort(key=lambda x: x[1], reverse=True)
    return final_best_rules_list


# --- Utility Functions ---
def analyze_cumulative_value(sorted_data: List[Tuple[str, int]], total_lines: int):
    """Performs Pareto analysis and prints suggestions for MAX_COUNT filtering."""
    if not sorted_data:
        print("[ANALYZE] No data to analyze.")
        return
        
    total_value = sum(count for _, count in sorted_data)
    cumulative_count = 0
    milestones: List[Tuple[int, int]] = []
    target_percentages = [50, 80, 90, 95] 
    next_target = 0
    
    for i, (_, count) in enumerate(sorted_data):
        cumulative_count += count
        current_percentage = (cumulative_count / total_value) * 100
        if next_target < len(target_percentages) and current_percentage >= target_percentages[next_target]:
            milestones.append((target_percentages[next_target], i + 1))
            next_target += 1
        if next_target >= len(target_percentages): break
            
    print("\n" + "#"*60)
    print("CUMULATIVE VALUE ANALYSIS (PARETO) - SUGGESTED CUTOFF LIMITS")
    print(f"Total value (line occurrences) after consolidation: {total_value:,}")
    print(f"Total number of unique rules: {len(sorted_data):,}")
    print("#"*60)

    for target, rules_needed in milestones:
        rules_percentage = (rules_needed / len(sorted_data)) * 100
        print(f"[{target}% OF VALUE]: Reached with {rules_needed:,} rules. ({rules_percentage:.2f}% of unique rules)")
    
    print("---")
    if milestones:
        last_milestone_rules = milestones[-1][1]
        print(f"[SUGGESTION] Consider using a limit of: {last_milestone_rules:,} or {int(last_milestone_rules * 1.1):,} for safety.")
    print("#"*60)
    
def read_file_data(input_filepath: str) -> List[str]:
    """Reads all data from a single file into RAM."""
    if not os.path.exists(input_filepath):
        print(f"Error: Input file '{input_filepath}' does not exist.")
        return []
    print(f"[+] Reading file: {input_filepath}")
    try:
        # Use 'ignore' for error handling if the file contains bad bytes
        with open(input_filepath, 'r', encoding='latin-1', errors='ignore') as f:
            data = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            return data
    except IOError as e:
        print(f"[-] File read error for {input_filepath}: {e}")
        return []

def process_disk_data(input_files: List[str]) -> Tuple[List[Tuple[str, int]], int]:
    """Reads, consolidates, and counts data using disk for intermediate storage."""
    all_data_temp_file: str = ""
    total_lines = 0

    print("\n[DISK MODE] Initiating disk-based processing to conserve RAM...")
    
    with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_f:
        all_data_temp_file = temp_f.name
        print(f"[DISK] Consolidating all input data into temporary file: {all_data_temp_file}")
        
        for input_file in input_files:
            try:
                with open(input_file, 'r', encoding='latin-1', errors='ignore') as f:
                    for line in f:
                        stripped_line = line.strip()
                        # Skip comments and empty lines
                        if stripped_line and not stripped_line.startswith('#'):
                            temp_f.write(stripped_line + '\n')
                            total_lines += 1
            except IOError as e:
                print(f"[-] File read error for {input_file}: {e}")
                
    if total_lines == 0:
        print("No valid data found across all files. Exiting disk mode.")
        if os.path.exists(all_data_temp_file): os.remove(all_data_temp_file)
        return [], 0

    print(f"[DISK] Total lines consolidated: {total_lines:,}")
    print("[DISK] Counting and sorting unique rules...")
    occurrence_counts: Counter = Counter()
    
    # We need to re-open the file for reading and counting
    try:
        with open(all_data_temp_file, 'r', encoding='utf-8') as f:
            # Note: total=total_lines might not be accurate for tqdm if lines were filtered
            for line in tqdm(f, total=total_lines, desc="Counting rules"):
                occurrence_counts[line.strip()] += 1
    except Exception as e:
        print(f"[-] Error reading from temporary file: {e}")
        
    sorted_data_textual: List[Tuple[str, int]] = occurrence_counts.most_common()

    try:
        os.remove(all_data_temp_file)
        print(f"[DISK] Cleaned up temporary file: {all_data_temp_file}")
    except OSError as e:
        print(f"[-] Error deleting temporary file: {e}")

    return sorted_data_textual, total_lines


# ==============================================================================
# C. MAIN PROCESS FUNCTION 
# ==============================================================================

def process_multiple_files(args: argparse.Namespace):
    
    print("\n" + "="*60)
    print(f"STARTING MULTI-FILE PROCESSING (Mode: {'DISK' if args.use_disk else 'RAM'})")
    print(f"Levenshtein Filter Max Dist: {args.levenshtein_max_dist}")
    print("="*60)
    
    input_files = args.input_files
    
    # 1. Reading, Combining, Counting, and Sorting Data 
    if args.use_disk:
        sorted_data_textual, total_lines = process_disk_data(input_files)
    else:
        all_data: List[str] = []
        for input_file in input_files:
            file_data = read_file_data(input_file)
            if file_data:
                all_data.extend(file_data)
        
        total_lines = len(all_data)
        if not all_data:
            print("\nNo valid data found. Exiting.")
            return

        occurrence_counts: Counter = Counter(all_data)
        sorted_data_textual: List[Tuple[str, int]] = occurrence_counts.most_common()
    
    if total_lines == 0:
        return

    # 2. Post-processing Stats and Analysis (Textual)
    unique_count_textual = len(sorted_data_textual)
    sorted_data = sorted_data_textual 
    
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
    
    analyze_cumulative_value(sorted_data_textual, total_lines)
    
    # 2.5. LEVENSHTEIN REDUNDANCY FILTER
    if args.levenshtein_max_dist > 0:
        sorted_data = apply_levenshtein_filter(sorted_data_textual, args.levenshtein_max_dist)
        unique_count = len(sorted_data)
        
        if unique_count != unique_count_textual:
              print(f"\n[LEVE] Levenshtein filter reduced the set from {unique_count_textual:,} to {unique_count:,} rules.")
              analyze_cumulative_value(sorted_data, total_lines) 

    unique_count = len(sorted_data)
    
    # 3. User Input for Filtering Mode
    min_count_threshold: int = 1
    max_rule_limit: int = unique_count
    mode_choice_1 = ''
    mode_choice_2 = ''

    print("\n" + "-"*60)
    print("RULE FILTERING: Choose Mode")
    print(" (1) Filter by MINIMUM OCCURRENCE")
    print(" (2) Filter by MAXIMUM NUMBER OF RULES (Statistical Cutoff - TOP N)")
    print(" (3) Filter by FUNCTIONAL REDUNDANCY (Logic Minimization) [RAM INTENSIVE]")
    print(" (4) **INVERSE MODE** - Save rules *BELOW* the MAX_COUNT limit (The 'Leftovers')")
    print(" (0/Enter) Save ALL unique rules")
    print("-"*60)
    
    while True:
        mode_choice_1 = input("Enter mode choice (1, 2, 3, 4, 0/Enter): ").strip()
        if mode_choice_1 in ['', '0', '1', '2', '3', '4']: break
        else: print("[-] Invalid choice. Please enter 1, 2, 3, 4, 0, or press Enter.")
            
    is_inverse_mode = (mode_choice_1 == '4')
    
    # --- LOGIC MINIMIZATION EXECUTION (MODE 3) ---
    if mode_choice_1 == '3':
        print("\n[WARNING] Functional Minimization (Mode 3) is always RAM intensive and uses multiprocessing.")
        sorted_data_functional = generate_functional_signatures(sorted_data) 
        sorted_data = sorted_data_functional
        unique_count = len(sorted_data)
        
        print(f"\n[MINIMIZATION] Logic minimization reduced unique count from {len(sorted_data_textual):,} to {unique_count:,} functional rules.")
        analyze_cumulative_value(sorted_data, total_lines) 

        print("\n" + "-"*60)
        print(f"FUNCTIONAL MINIMIZATION APPLIED. New unique count: {unique_count:,}")
        print("Choose further statistical filtering:")
        print(" (1) Filter by MINIMUM TOTAL OCCURRENCE (of the functional group)")
        print(" (2) Filter by MAXIMUM NUMBER OF FUNCTIONAL RULES (TOP N)")
        print(" (4) **INVERSE MODE** - Save rules *BELOW* the MAX_COUNT limit (The 'Leftovers')")
        print(" (0/Enter) Save ALL functional rules")
        print("-"*60)
        
        while True:
            mode_choice_2 = input("Enter mode choice (1, 2, 4, 0/Enter): ").strip()
            if mode_choice_2 in ['', '0', '1', '2', '4']: break
            else: print("[-] Invalid choice. Please enter 1, 2, 4, 0, or press Enter.")

        if mode_choice_2 in ['', '0']: pass
        elif mode_choice_2 == '1': mode_choice_1 = '1'
        elif mode_choice_2 == '2': mode_choice_1 = '2'
        elif mode_choice_2 == '4':
            mode_choice_1 = '4'
            is_inverse_mode = True 

    # --- Execute MIN_COUNT or MAX_COUNT Logic ---
    max_rule_limit = unique_count

    if mode_choice_1 in ['', '0']:
        min_count_threshold = 1
        max_rule_limit = unique_count
    
    if mode_choice_1 == '1':
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
                else: print(f"[-] The minimum count must be 1 or higher.")
            except ValueError: print("[-] Invalid format. Please enter an integer.")

    elif mode_choice_1 == '2' or mode_choice_1 == '4':
        while True:
            mode_label = "**INVERSE**" if mode_choice_1 == '4' else "MAX_COUNT"
            limit_input = input(f"[{mode_label} MODE] Enter the number of rules to KEEP/SKIP (1 to {unique_count:,}): ").strip()
            try:
                max_rule_limit = int(limit_input)
                if 1 <= max_rule_limit <= unique_count:
                    min_count_threshold = 1
                    print(f"[+] Selected limit: {max_rule_limit:,}.")
                    break
                else: print(f"[-] The number must be between 1 and {unique_count:,}.")
            except ValueError: print("[-] Invalid format. Please enter an integer.")

    # --- 4. Applying the filter based on the chosen mode ---
    data_after_min_count_filter = []
    
    for item, count in sorted_data:
        if count >= min_count_threshold:
            data_after_min_count_filter.append((item, count))
        else: break
            
    if is_inverse_mode:
        final_data_to_write = data_after_min_count_filter[max_rule_limit:]
        skipped_count = max_rule_limit
        print(f"\n[INVERSE RESULT] Saved {len(final_data_to_write):,} rules (the 'Leftovers').")
        print(f"[INVERSE RESULT] {skipped_count:,} TOP rules were **intentionally skipped**.")
        
    else:
        final_data_to_write = data_after_min_count_filter[:max_rule_limit]
        removed_count = unique_count - len(final_data_to_write)
        print(f"\n[RESULT] Final number of rules to be saved: {len(final_data_to_write):,}")
        if removed_count > 0:
            print(f"[RESULT] {removed_count:,} unique rules were removed from the initial set of {unique_count:,}.")
    
    # --- 5. Saving the data to the new file or STDOUT ---
    final_write_count = len(final_data_to_write)
    
    if args.output_stdout:
        print("\nSaving filtered consolidated data to: STDOUT", file=sys.stderr)
        for item, _ in final_data_to_write:
            sys.stdout.write(f"{item}\n")
        print(f"Successfully wrote {final_write_count:,} filtered entries to STDOUT.", file=sys.stderr)
        print("\n" + "="*60, file=sys.stderr)
        print("PROCESSING COMPLETE", file=sys.stderr)
        print("="*60, file=sys.stderr)
        return


    # --- File Saving Logic ---
    first_basename = os.path.basename(os.path.splitext(input_files[0])[0])
    
    filter_parts = []
    if args.levenshtein_max_dist > 0: filter_parts.append(f"L{args.levenshtein_max_dist}")
    
    # Naming logic is preserved
    if mode_choice_1 == '3' and is_inverse_mode: filter_parts.append(f"F_INVERSE_TOP_{max_rule_limit}")
    elif mode_choice_1 == '3' and mode_choice_2 == '2': filter_parts.append(f"F_TOP_{max_rule_limit}")
    elif mode_choice_1 == '3' and mode_choice_2 == '1': filter_parts.append(f"F_MIN_{min_count_threshold}")
    elif is_inverse_mode: filter_parts.append(f"INVERSE_TOP_{max_rule_limit}")
    elif mode_choice_1 == '2': filter_parts.append(f"TOP_{max_rule_limit}")
    elif mode_choice_1 == '1': filter_parts.append(f"MIN_{min_count_threshold}")
    elif not filter_parts: filter_parts.append("slimmed")

    filter_str = "_".join(filter_parts)
    
    output_filepath = f"{first_basename}_CONSOLIDATED_{filter_str}.rule"
    if filter_str == "slimmed": output_filepath = f"{first_basename}_slimmed.rule"
    
    input_dir = os.path.dirname(input_files[0])
    if input_dir: output_filepath = os.path.join(input_dir, output_filepath)

    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            print(f"\nSaving filtered consolidated data to: {output_filepath}")
            for item, _ in final_data_to_write: f.write(f"{item}\n")
            print(f"Successfully saved {final_write_count:,} filtered entries.")
            print("\n" + "="*60)
            print("PROCESSING COMPLETE")
            print("="*60)
            
    except IOError as e:
        print(f"File write error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__, # Use the script's docstring for description
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input_files', nargs='+', help='Paths to the debug hashcat rule files to process.')
    parser.add_argument('-d', '--use-disk', action='store_true', help='Use disk (temp files) for initial consolidation to save RAM.')
    parser.add_argument('-ld', '--levenshtein-max-dist', type=int, default=0, 
                        help='Filters rules based on Levenshtein distance. Rules too close (<= DIST) to a better-ranked rule are removed. 0 = disabled (Default).')
    parser.add_argument('-o', '--output-stdout', action='store_true', 
                        help='Output the result to standard output (STDOUT) instead of creating a file. Informational messages are sent to STDERR.')
    
    args = parser.parse_args()
    process_multiple_files(args)

