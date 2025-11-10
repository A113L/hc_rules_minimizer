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
- NEW: Mode 5 - OpenCL-based rules validation and cleanup (hashcat standards).
- NEW: Mode 6 - OpenCL-accelerated Levenshtein distance filtering.
- NEW: GPU-accelerated rule counting for both disk and RAM modes.
- NEW: Option to output results to STDOUT for piping (-o / --output-stdout).
- NEW: Recursive folder search for rule files (max depth 3).
- NEW: Smart processing selection - CPU for large datasets, GPU for smaller ones.
'''
import sys
import os
import re
import glob
from collections import Counter
from typing import List, Tuple, Dict, Callable, Any, Set
import argparse
import tempfile
import multiprocessing
from tqdm import tqdm
import itertools

# --- OPENCL IMPLEMENTATION CHECK ---
PYOPENCL_AVAILABLE = False
try:
    import pyopencl as cl
    import numpy as np
    PYOPENCL_AVAILABLE = True
    print("[INFO] PyOpenCL found. OpenCL-based validation available as Mode 5 & 6.")
    print("[INFO] GPU-accelerated rule counting enabled.")
except ImportError:
    print("[WARNING] PyOpenCL not found. Modes 5 & 6 (OpenCL validation/Levenshtein) will be disabled.")
    print("[WARNING] GPU-accelerated rule counting disabled.")

# --- NUMPY IMPLEMENTATION CHECK ---
NUMPY_AVAILABLE = False
try:
    import numpy as np
    NUMPY_AVAILABLE = True
    print("[INFO] NumPy found. Using optimized Levenshtein distance calculation.")
except ImportError:
    if not PYOPENCL_AVAILABLE:
        print("[WARNING] NumPy not found. Falling back to slower pure Python Levenshtein distance calculation.")

# ==============================================================================
# A. HASHCAT RULE ENGINE SIMULATION (From the working script)
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
# B. HASHCAT RULE CLEANUP IMPLEMENTATION (Based on cleanup-rules.c)
# ==============================================================================

class HashcatRuleCleaner:
    """
    Implements hashcat's rule validation and cleanup logic.
    Based on the official cleanup-rules.c from hashcat.
    """
    
    # Rule operation constants (from hashcat)
    RULE_OP_MANGLE_NOOP             = ':'
    RULE_OP_MANGLE_LREST            = 'l'
    RULE_OP_MANGLE_UREST            = 'u'
    RULE_OP_MANGLE_LREST_UFIRST     = 'c'
    RULE_OP_MANGLE_UREST_LFIRST     = 'C'
    RULE_OP_MANGLE_TREST            = 't'
    RULE_OP_MANGLE_TOGGLE_AT        = 'T'
    RULE_OP_MANGLE_REVERSE          = 'r'
    RULE_OP_MANGLE_DUPEWORD         = 'd'
    RULE_OP_MANGLE_DUPEWORD_TIMES   = 'p'
    RULE_OP_MANGLE_REFLECT          = 'f'
    RULE_OP_MANGLE_ROTATE_LEFT      = '{'
    RULE_OP_MANGLE_ROTATE_RIGHT     = '}'
    RULE_OP_MANGLE_APPEND           = '$'
    RULE_OP_MANGLE_PREPEND          = '^'
    RULE_OP_MANGLE_DELETE_FIRST     = '['
    RULE_OP_MANGLE_DELETE_LAST      = ']'
    RULE_OP_MANGLE_DELETE_AT        = 'D'
    RULE_OP_MANGLE_EXTRACT          = 'x'
    RULE_OP_MANGLE_INSERT           = 'i'
    RULE_OP_MANGLE_OVERSTRIKE       = 'o'
    RULE_OP_MANGLE_TRUNCATE_AT      = "'"
    RULE_OP_MANGLE_REPLACE          = 's'
    RULE_OP_MANGLE_PURGECHAR        = '@'
    RULE_OP_MANGLE_TOGGLECASE_REC   = 'a'
    RULE_OP_MANGLE_DUPECHAR_FIRST   = 'z'
    RULE_OP_MANGLE_DUPECHAR_LAST    = 'Z'
    RULE_OP_MANGLE_DUPECHAR_ALL     = 'q'
    RULE_OP_MANGLE_EXTRACT_MEMORY   = 'X'
    RULE_OP_MANGLE_APPEND_MEMORY    = '4'
    RULE_OP_MANGLE_PREPEND_MEMORY   = '6'
    RULE_OP_MEMORIZE_WORD           = 'M'
    RULE_OP_REJECT_LESS             = '<'
    RULE_OP_REJECT_GREATER          = '>'
    RULE_OP_REJECT_CONTAIN          = '!'
    RULE_OP_REJECT_NOT_CONTAIN      = '/'
    RULE_OP_REJECT_EQUAL_FIRST      = '('
    RULE_OP_REJECT_EQUAL_LAST       = ')'
    RULE_OP_REJECT_EQUAL_AT         = '='
    RULE_OP_REJECT_CONTAINS         = '%'
    RULE_OP_REJECT_MEMORY           = 'Q'
    # hashcat only
    RULE_OP_MANGLE_SWITCH_FIRST     = 'k'
    RULE_OP_MANGLE_SWITCH_LAST      = 'K'
    RULE_OP_MANGLE_SWITCH_AT        = '*'
    RULE_OP_MANGLE_CHR_SHIFTL       = 'L'
    RULE_OP_MANGLE_CHR_SHIFTR       = 'R'
    RULE_OP_MANGLE_CHR_INCR         = '+'
    RULE_OP_MANGLE_CHR_DECR         = '-'
    RULE_OP_MANGLE_REPLACE_NP1      = '.'
    RULE_OP_MANGLE_REPLACE_NM1      = ','
    RULE_OP_MANGLE_DUPEBLOCK_FIRST  = 'y'
    RULE_OP_MANGLE_DUPEBLOCK_LAST   = 'Y'
    RULE_OP_MANGLE_TITLE            = 'E'

    # Maximum rules per line
    MAX_CPU_RULES = 255
    MAX_GPU_RULES = 255

    def __init__(self, mode: int = 1):
        """
        Initialize the rule cleaner.
        mode: 1 = CPU rules, 2 = GPU rules
        """
        if mode not in [1, 2]:
            raise ValueError("Mode must be 1 (CPU) or 2 (GPU)")
        self.mode = mode
        self.max_rules = self.MAX_CPU_RULES if mode == 1 else self.MAX_GPU_RULES

    @staticmethod
    def class_num(c: str) -> bool:
        """Check if character is a digit."""
        return c >= '0' and c <= '9'

    @staticmethod
    def class_upper(c: str) -> bool:
        """Check if character is uppercase letter."""
        return c >= 'A' and c <= 'Z'

    @staticmethod
    def conv_ctoi(c: str) -> int:
        """Convert character to integer (base36)."""
        if HashcatRuleCleaner.class_num(c):
            return ord(c) - ord('0')
        elif HashcatRuleCleaner.class_upper(c):
            return ord(c) - ord('A') + 10
        return -1

    def is_gpu_denied_op(self, op: str) -> bool:
        """Check if operation is denied on GPU."""
        gpu_denied_ops = {
            self.RULE_OP_MANGLE_EXTRACT_MEMORY,
            self.RULE_OP_MANGLE_APPEND_MEMORY,
            self.RULE_OP_MANGLE_PREPEND_MEMORY,
            self.RULE_OP_MEMORIZE_WORD,
            self.RULE_OP_REJECT_LESS,
            self.RULE_OP_REJECT_GREATER,
            self.RULE_OP_REJECT_CONTAIN,
            self.RULE_OP_REJECT_NOT_CONTAIN,
            self.RULE_OP_REJECT_EQUAL_FIRST,
            self.RULE_OP_REJECT_EQUAL_LAST,
            self.RULE_OP_REJECT_EQUAL_AT,
            self.RULE_OP_REJECT_CONTAINS,
            self.RULE_OP_REJECT_MEMORY
        }
        return op in gpu_denied_ops

    def validate_rule(self, rule_line: str) -> bool:
        """
        Validate a single rule line according to hashcat standards.
        Returns True if rule is valid, False otherwise.
        """
        # Remove spaces and check if empty
        clean_line = rule_line.replace(' ', '')
        if not clean_line:
            return False

        rc = 0
        cnt = 0
        pos = 0
        line_len = len(clean_line)

        while pos < line_len:
            op = clean_line[pos]
            
            # Skip spaces (though we already removed them)
            if op == ' ':
                pos += 1
                continue

            # Validate operation and parameters
            try:
                if op == self.RULE_OP_MANGLE_NOOP:
                    pass
                elif op == self.RULE_OP_MANGLE_LREST:
                    pass
                elif op == self.RULE_OP_MANGLE_UREST:
                    pass
                elif op == self.RULE_OP_MANGLE_LREST_UFIRST:
                    pass
                elif op == self.RULE_OP_MANGLE_UREST_LFIRST:
                    pass
                elif op == self.RULE_OP_MANGLE_TREST:
                    pass
                elif op == self.RULE_OP_MANGLE_TOGGLE_AT:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_REVERSE:
                    pass
                elif op == self.RULE_OP_MANGLE_DUPEWORD:
                    pass
                elif op == self.RULE_OP_MANGLE_DUPEWORD_TIMES:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_REFLECT:
                    pass
                elif op == self.RULE_OP_MANGLE_ROTATE_LEFT:
                    pass
                elif op == self.RULE_OP_MANGLE_ROTATE_RIGHT:
                    pass
                elif op == self.RULE_OP_MANGLE_APPEND:
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_PREPEND:
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_DELETE_FIRST:
                    pass
                elif op == self.RULE_OP_MANGLE_DELETE_LAST:
                    pass
                elif op == self.RULE_OP_MANGLE_DELETE_AT:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_EXTRACT:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_INSERT:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_OVERSTRIKE:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_TRUNCATE_AT:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_REPLACE:
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_PURGECHAR:
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_TOGGLECASE_REC:
                    pass
                elif op == self.RULE_OP_MANGLE_DUPECHAR_FIRST:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_DUPECHAR_LAST:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_DUPECHAR_ALL:
                    pass
                elif op == self.RULE_OP_MANGLE_DUPEBLOCK_FIRST:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_DUPEBLOCK_LAST:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_SWITCH_FIRST:
                    pass
                elif op == self.RULE_OP_MANGLE_SWITCH_LAST:
                    pass
                elif op == self.RULE_OP_MANGLE_SWITCH_AT:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_CHR_SHIFTL:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_CHR_SHIFTR:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_CHR_INCR:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_CHR_DECR:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_REPLACE_NP1:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_REPLACE_NM1:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                elif op == self.RULE_OP_MANGLE_TITLE:
                    pass
                elif op == self.RULE_OP_MANGLE_EXTRACT_MEMORY:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_MANGLE_APPEND_MEMORY:
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_MANGLE_PREPEND_MEMORY:
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_MEMORIZE_WORD:
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_REJECT_LESS:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_REJECT_GREATER:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_REJECT_CONTAIN:
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_REJECT_NOT_CONTAIN:
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_REJECT_EQUAL_FIRST:
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_REJECT_EQUAL_LAST:
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_REJECT_EQUAL_AT:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_REJECT_CONTAINS:
                    pos += 1
                    if pos >= line_len or self.conv_ctoi(clean_line[pos]) == -1:
                        rc = -1
                    pos += 1
                    if pos >= line_len:
                        rc = -1
                    if self.mode == 2:  # GPU mode
                        rc = -1
                elif op == self.RULE_OP_REJECT_MEMORY:
                    if self.mode == 2:  # GPU mode
                        rc = -1
                else:
                    rc = -1  # Unknown operation
            except IndexError:
                rc = -1

            if rc == -1:
                break

            cnt += 1
            pos += 1

            # Check rule count limits
            if cnt > self.max_rules:
                rc = -1
                break

        return rc == 0

    def clean_rules(self, rules_data: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
        """
        Clean and validate rules according to hashcat standards.
        Returns only valid rules.
        """
        print(f"[CLEANUP] Validating {len(rules_data):,} rules for {'GPU' if self.mode == 2 else 'CPU'} compatibility...")
        
        valid_rules = []
        invalid_count = 0
        
        for rule, count in tqdm(rules_data, desc="Validating rules"):
            if self.validate_rule(rule):
                valid_rules.append((rule, count))
            else:
                invalid_count += 1
        
        print(f"[CLEANUP] Removed {invalid_count:,} invalid rules. {len(valid_rules):,} valid rules remaining.")
        return valid_rules

# ==============================================================================
# C. FUNCTIONAL MINIMIZATION WITH HASHCAT RULE ENGINE
# ==============================================================================

# Test vector for functional minimization
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

def functional_minimization(data: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """
    Functional minimization using actual hashcat rule engine simulation.
    This removes rules that produce identical outputs for all test vectors.
    """
    print("\n[FUNCTIONAL MINIMIZATION] Starting logic-based redundancy removal...")
    print("[WARNING] This operation is RAM intensive and may take significant time for large datasets.")
    
    if not data:
        return data
    
    # For very large datasets, warn the user
    if len(data) > 10000:
        print(f"[WARNING] Large dataset detected ({len(data):,} rules).")
        response = input("Continue with functional minimization? (y/N): ").strip().lower()
        if response not in ['y', 'yes']:
            print("[INFO] Skipping functional minimization.")
            return data
    
    print(f"[INFO] Using hashcat rule engine simulation with test vector (Length: {len(TEST_VECTOR)})")
    
    signature_map: Dict[str, List[Tuple[str, int]]] = {}
    
    num_processes = multiprocessing.cpu_count()
    print(f"[MP] Using {num_processes} processes for functional simulation.")

    with multiprocessing.Pool(processes=num_processes) as pool:
        results = list(tqdm(
            pool.imap(worker_generate_signature, data),
            total=len(data),
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
    
    removed_count = len(data) - len(final_best_rules_list)
    print(f"[FUNCTIONAL MINIMIZATION] Removed {removed_count:,} functionally redundant rules.")
    print(f"[FUNCTIONAL MINIMIZATION] Final count: {len(final_best_rules_list):,} unique functional rules.")
    
    return final_best_rules_list

# ==============================================================================
# D. FILE DISCOVERY FUNCTIONS
# ==============================================================================

def find_rule_files(paths: List[str], max_depth: int = 3) -> List[str]:
    """
    Recursively find rule files in directories (max depth 3).
    Supports .rule, .txt files and also looks for common hashcat rule file patterns.
    """
    rule_files = []
    rule_extensions = {'.rule', '.rules', '.hr', '.hashcat', '.txt'}
    
    for path in paths:
        if os.path.isfile(path):
            # Single file provided
            file_ext = os.path.splitext(path.lower())[1]
            if file_ext in rule_extensions:
                rule_files.append(path)
                print(f"[FOUND] Rule file: {path}")
            else:
                print(f"[SKIP] Not a rule file (wrong extension): {path}")
        
        elif os.path.isdir(path):
            # Directory provided - search recursively
            print(f"[SEARCH] Scanning directory: {path} (max depth: {max_depth})")
            found_in_dir = 0
            
            for depth in range(max_depth + 1):
                # Search for all rule extensions
                for ext in rule_extensions:
                    pattern = path + '/*' * depth + '*' + ext
                    depth_files = glob.glob(pattern, recursive=True)
                    
                    for file_path in depth_files:
                        if os.path.isfile(file_path) and file_path not in rule_files:
                            rule_files.append(file_path)
                            found_in_dir += 1
                            if depth == 0:
                                print(f"[FOUND] Rule file: {file_path}")
                            else:
                                print(f"[FOUND] Rule file (depth {depth}): {file_path}")
            
            if found_in_dir == 0:
                print(f"[INFO] No rule files found in: {path}")
            else:
                print(f"[INFO] Found {found_in_dir} rule files in: {path}")
        
        else:
            print(f"[ERROR] Path not found: {path}")
    
    # Remove duplicates and sort
    rule_files = sorted(list(set(rule_files)))
    print(f"\n[TOTAL] Found {len(rule_files)} unique rule files to process")
    return rule_files

# ==============================================================================
# E. SMART PROCESSING SELECTION - CPU FOR LARGE DATASETS, GPU FOR SMALLER ONES
# ==============================================================================

def get_processing_recommendation(total_rules: int) -> str:
    """
    Determine the recommended processing method based on dataset size.
    """
    if total_rules <= 10000:
        return "GPU"  # Small datasets benefit from GPU acceleration
    elif total_rules <= 100000:
        return "BOTH"  # Medium datasets can use either
    else:
        return "CPU"  # Large datasets are better on CPU to avoid GPU memory issues

def ask_processing_method(total_rules: int, use_gpu_default: bool = True) -> str:
    """
    Ask user for processing method with intelligent recommendations.
    """
    recommendation = get_processing_recommendation(total_rules)
    
    print(f"\n[PROCESSING SELECTION] Dataset size: {total_rules:,} rules")
    print(f"[RECOMMENDATION] Based on size, recommended method: {recommendation}")
    print("\nAvailable processing methods:")
    print(" (1) CPU Processing - Better for large datasets (>100K rules)")
    print(" (2) GPU Processing - Faster for small/medium datasets (<100K rules)")
    print(" (3) Auto Selection - Let the script choose the best method")
    
    if recommendation == "GPU":
        default_choice = "2"
        print(f"\n[SUGGESTION] For {total_rules:,} rules, GPU is recommended for best performance")
    elif recommendation == "CPU":
        default_choice = "1" 
        print(f"\n[SUGGESTION] For {total_rules:,} rules, CPU is recommended to avoid GPU memory issues")
    else:
        default_choice = "3"
        print(f"\n[SUGGESTION] For {total_rules:,} rules, either method works well")
    
    while True:
        choice = input(f"Choose processing method (1=CPU, 2=GPU, 3=Auto) [{default_choice}]: ").strip()
        if not choice:
            choice = default_choice
            
        if choice == '1':
            return "CPU"
        elif choice == '2':
            return "GPU"
        elif choice == '3':
            return "AUTO"
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

# ==============================================================================
# F. OPTIMIZED GPU-ACCELERATED RULE COUNTING
# ==============================================================================

class GPURuleCounter:
    def __init__(self):
        if not PYOPENCL_AVAILABLE:
            raise RuntimeError("PyOpenCL not available")
        
        # Initialize OpenCL context and queue
        self.ctx = cl.create_some_context()
        self.queue = cl.CommandQueue(self.ctx)
        
        # Get device info for proper work group sizing
        self.device = self.ctx.devices[0]
        self.max_work_group_size = self.device.max_work_group_size
        
        print(f"[GPU] Device: {self.device.name}")
        print(f"[GPU] Max work group size: {self.max_work_group_size}")
        
        # Build the optimized OpenCL program for rule counting
        self.program = cl.Program(self.ctx, """
        // Optimized hash function for strings (djb2 with early exit)
        unsigned long djb2_hash(__global const unsigned char* str, unsigned int max_len) {
            unsigned long hash = 5381;
            for (unsigned int i = 0; i < max_len; i++) {
                if (str[i] == 0 || str[i] == '\\n') break;
                hash = ((hash << 5) + hash) + str[i]; // hash * 33 + c
            }
            return hash;
        }

        __kernel void count_rules_gpu_simple(
            __global const unsigned char* rules_data,
            __global unsigned long* rule_hashes,
            __global unsigned int* rule_lengths,
            const unsigned int num_rules,
            const unsigned int max_rule_len)
        {
            unsigned int global_id = get_global_id(0);
            if (global_id >= num_rules) return;

            __global const unsigned char* rule_ptr = rules_data + global_id * max_rule_len;
            
            // Calculate rule length and hash in single pass
            unsigned int rule_len = 0;
            unsigned long hash = 5381;
            
            for (unsigned int i = 0; i < max_rule_len; i++) {
                unsigned char c = rule_ptr[i];
                if (c == 0 || c == '\\n') {
                    rule_len = i;
                    break;
                }
                hash = ((hash << 5) + hash) + c;
                rule_len++;
            }
            
            // Store results
            rule_lengths[global_id] = rule_len;
            rule_hashes[global_id] = (rule_len > 0) ? hash : 0;
        }

        __kernel void count_unique_rules_simple(
            __global const unsigned long* rule_hashes,
            __global const unsigned int* rule_lengths,
            __global unsigned char* unique_flags,
            __global unsigned int* occurrence_counts,
            const unsigned int num_rules)
        {
            unsigned int global_id = get_global_id(0);
            if (global_id >= num_rules) return;

            unsigned long current_hash = rule_hashes[global_id];
            unsigned int current_length = rule_lengths[global_id];
            
            if (current_hash == 0 || current_length == 0) {
                unique_flags[global_id] = 0;
                occurrence_counts[global_id] = 0;
                return;
            }

            // Check if this rule is unique by comparing with all previous rules
            unsigned char is_unique = 1;
            unsigned int count = 1;

            for (unsigned int i = 0; i < global_id; i++) {
                if (rule_hashes[i] == current_hash && rule_lengths[i] == current_length) {
                    is_unique = 0;
                    count++;
                    break;
                }
            }

            unique_flags[global_id] = is_unique;
            occurrence_counts[global_id] = count;
        }
        """).build()
        
        # Cache kernel instances to avoid repeated retrieval
        self.hash_kernel = self.program.count_rules_gpu_simple
        self.unique_kernel = self.program.count_unique_rules_simple
    
    def count_rules_gpu_ram(self, rules: List[str]) -> List[Tuple[str, int]]:
        """
        Count rule occurrences using GPU acceleration (optimized for smaller datasets).
        """
        print(f"[GPU] Counting {len(rules):,} rules using GPU acceleration...")
        
        if not rules:
            return []
        
        # Prepare rules data
        print("[GPU] Preparing rules data...")
        max_rule_len = max(len(rule) for rule in rules) + 1
        rules_flat = bytearray()
        
        for rule in tqdm(rules, desc="Preparing rules for GPU"):
            rule_bytes = rule.encode('latin-1', 'ignore')
            rules_flat.extend(rule_bytes)
            rules_flat.extend(b'\x00' * (max_rule_len - len(rule_bytes)))
        
        # Create OpenCL buffers
        print("[GPU] Creating GPU buffers...")
        rules_buf = cl.Buffer(self.ctx, cl.mem_flags.READ_ONLY | cl.mem_flags.COPY_HOST_PTR, 
                             hostbuf=bytes(rules_flat))
        
        # Use optimized data types
        rule_hashes = np.zeros(len(rules), dtype=np.uint64)
        rule_lengths = np.zeros(len(rules), dtype=np.uint32)
        unique_flags = np.zeros(len(rules), dtype=np.uint8)
        occurrence_counts = np.zeros(len(rules), dtype=np.uint32)
        
        hashes_buf = cl.Buffer(self.ctx, cl.mem_flags.WRITE_ONLY, rule_hashes.nbytes)
        lengths_buf = cl.Buffer(self.ctx, cl.mem_flags.WRITE_ONLY, rule_lengths.nbytes)
        unique_buf = cl.Buffer(self.ctx, cl.mem_flags.WRITE_ONLY, unique_flags.nbytes)
        counts_buf = cl.Buffer(self.ctx, cl.mem_flags.WRITE_ONLY, occurrence_counts.nbytes)
        
        # Execute kernels with safe work group sizing
        global_size = (len(rules),)
        
        print("[GPU] Executing hash calculation kernel...")
        try:
            # Try with a conservative local size
            local_size = (min(64, len(rules)),) if len(rules) >= 64 else None
            self.hash_kernel(self.queue, global_size, local_size,
                           rules_buf, hashes_buf, lengths_buf,
                           np.uint32(len(rules)), np.uint32(max_rule_len))
        except cl.LogicError:
            # Fall back to no local size
            self.hash_kernel(self.queue, global_size, None,
                           rules_buf, hashes_buf, lengths_buf,
                           np.uint32(len(rules)), np.uint32(max_rule_len))
        
        print("[GPU] Executing unique counting kernel...")
        try:
            self.unique_kernel(self.queue, global_size, local_size,
                             hashes_buf, lengths_buf, unique_buf, counts_buf,
                             np.uint32(len(rules)))
        except cl.LogicError:
            self.unique_kernel(self.queue, global_size, None,
                             hashes_buf, lengths_buf, unique_buf, counts_buf,
                             np.uint32(len(rules)))
        
        # Read results efficiently
        print("[GPU] Reading results...")
        cl.enqueue_copy(self.queue, unique_flags, unique_buf).wait()
        cl.enqueue_copy(self.queue, occurrence_counts, counts_buf).wait()
        
        # Build results
        print("[GPU] Processing results...")
        rule_count_map = {}
        
        for i, rule in tqdm(enumerate(rules), total=len(rules), desc="Processing GPU results"):
            if unique_flags[i] == 1:
                rule_count_map[rule] = occurrence_counts[i]
        
        # Convert to sorted list
        sorted_rules = sorted(rule_count_map.items(), key=lambda x: x[1], reverse=True)
        
        print(f"[GPU] Counting complete: {len(sorted_rules):,} unique rules found")
        return sorted_rules

# ==============================================================================
# G. OPTIMIZED CPU RULE COUNTING (FOR LARGE DATASETS)
# ==============================================================================

def count_rules_cpu_optimized(rules: List[str]) -> List[Tuple[str, int]]:
    """
    Count rule occurrences using optimized CPU method (better for large datasets).
    """
    print(f"[CPU] Counting {len(rules):,} rules using optimized CPU method...")
    
    if not rules:
        return []
    
    # Use Counter for efficient counting
    print("[CPU] Counting occurrences...")
    occurrence_counts = Counter(rules)
    
    # Convert to sorted list
    print("[CPU] Sorting results...")
    sorted_rules = occurrence_counts.most_common()
    
    print(f"[CPU] Counting complete: {len(sorted_rules):,} unique rules found")
    return sorted_rules

def count_rules_cpu_chunked(rules: List[str], chunk_size: int = 1000000) -> List[Tuple[str, int]]:
    """
    Count rule occurrences using chunked CPU method for very large datasets.
    """
    print(f"[CPU] Counting {len(rules):,} rules using chunked CPU method...")
    
    if not rules:
        return []
    
    total_chunks = (len(rules) + chunk_size - 1) // chunk_size
    final_counter = Counter()
    
    for chunk_idx in range(total_chunks):
        start_idx = chunk_idx * chunk_size
        end_idx = min((chunk_idx + 1) * chunk_size, len(rules))
        
        chunk_rules = rules[start_idx:end_idx]
        chunk_counter = Counter(chunk_rules)
        final_counter.update(chunk_counter)
        
        print(f"[CPU] Processed chunk {chunk_idx + 1}/{total_chunks} ({end_idx:,} rules)")
    
    # Convert to sorted list
    print("[CPU] Sorting final results...")
    sorted_rules = final_counter.most_common()
    
    print(f"[CPU] Counting complete: {len(sorted_rules):,} unique rules found")
    return sorted_rules

# ==============================================================================
# H. SMART PROCESSING DISPATCHER
# ==============================================================================

def smart_count_rules(rules: List[str], method: str = "AUTO") -> List[Tuple[str, int]]:
    """
    Smart rule counting that chooses the best method based on dataset size and user preference.
    """
    total_rules = len(rules)
    
    if total_rules == 0:
        return []
    
    # Auto selection logic
    if method == "AUTO":
        if total_rules <= 50000 and PYOPENCL_AVAILABLE:
            method = "GPU"
        elif total_rules <= 1000000:
            method = "CPU"
        else:
            method = "CPU_CHUNKED"
    
    print(f"\n[PROCESSING] Using {method} method for {total_rules:,} rules")
    
    if method == "GPU" and PYOPENCL_AVAILABLE:
        try:
            if total_rules > 500000:
                print(f"[WARNING] GPU processing recommended for datasets <500K rules")
                print(f"[WARNING] Current dataset: {total_rules:,} rules - consider using CPU")
                
                response = input("Continue with GPU anyway? (y/N): ").strip().lower()
                if response not in ['y', 'yes']:
                    print("Switching to CPU method...")
                    method = "CPU"
            
            if method == "GPU":
                counter = GPURuleCounter()
                return counter.count_rules_gpu_ram(rules)
        except Exception as e:
            print(f"[WARNING] GPU counting failed: {e}. Falling back to CPU.")
            method = "CPU"
    
    if method == "CPU":
        if total_rules > 2000000:
            print(f"[INFO] Large dataset detected ({total_rules:,} rules), using chunked CPU method")
            return count_rules_cpu_chunked(rules)
        else:
            return count_rules_cpu_optimized(rules)
    
    elif method == "CPU_CHUNKED":
        return count_rules_cpu_chunked(rules)
    
    else:
        # Fallback to CPU if GPU is not available or method is invalid
        print(f"[WARNING] Invalid method '{method}', falling back to CPU")
        return count_rules_cpu_optimized(rules)

# ==============================================================================
# I. MAIN PROCESSING FUNCTIONS WITH SMART SELECTION
# ==============================================================================

def read_file_data(input_filepath: str) -> List[str]:
    """Reads all data from a single file into RAM."""
    if not os.path.exists(input_filepath):
        print(f"Error: Input file '{input_filepath}' does not exist.")
        return []
    print(f"[+] Reading file: {input_filepath}")
    try:
        with open(input_filepath, 'r', encoding='latin-1', errors='ignore') as f:
            data = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            return data
    except IOError as e:
        print(f"[-] File read error for {input_filepath}: {e}")
        return []

def process_disk_data(input_files: List[str], processing_method: str = "AUTO") -> Tuple[List[Tuple[str, int]], int]:
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
                    for line in tqdm(f, desc=f"Reading {os.path.basename(input_file)}", unit="lines"):
                        stripped_line = line.strip()
                        if stripped_line and not stripped_line.startswith('#'):
                            temp_f.write(stripped_line + '\n')
                            total_lines += 1
            except IOError as e:
                print(f"[-] File read error for {input_file}: {e}")
                
    if total_lines == 0:
        print("No valid data found across all files. Exiting disk mode.")
        if os.path.exists(all_data_temp_file): 
            os.remove(all_data_temp_file)
        return [], 0

    print(f"[DISK] Total lines consolidated: {total_lines:,}")
    
    # Read all rules from temp file for processing
    all_rules = []
    with open(all_data_temp_file, 'r', encoding='utf-8', errors='ignore') as f:
        for line in tqdm(f, total=total_lines, desc="Reading rules for processing"):
            stripped_line = line.strip()
            if stripped_line and not stripped_line.startswith('#'):
                all_rules.append(stripped_line)
    
    # Use smart counting based on dataset size
    sorted_data = smart_count_rules(all_rules, processing_method)
    
    # Clean up temp file
    try:
        os.remove(all_data_temp_file)
        print(f"[DISK] Cleaned up temporary file: {all_data_temp_file}")
    except OSError as e:
        print(f"[-] Error deleting temporary file: {e}")

    return sorted_data, total_lines

def process_ram_data(input_files: List[str], processing_method: str = "AUTO") -> Tuple[List[Tuple[str, int]], int]:
    """Process data entirely in RAM with smart processing selection."""
    all_data: List[str] = []
    for input_file in input_files:
        file_data = read_file_data(input_file)
        if file_data:
            all_data.extend(file_data)
    
    total_lines = len(all_data)
    if not all_data:
        print("\nNo valid data found. Exiting.")
        return [], 0

    # Use smart counting based on dataset size
    sorted_data = smart_count_rules(all_data, processing_method)
    
    return sorted_data, total_lines

# ==============================================================================
# J. LEVENSHTEIN FILTERING
# ==============================================================================

def levenshtein_distance(s1: str, s2: str) -> int:
    """Calculate Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

def levenshtein_filter(data: List[Tuple[str, int]], max_distance: int = 2) -> List[Tuple[str, int]]:
    """
    Filter rules based on Levenshtein distance to remove similar rules.
    """
    print(f"\n[LEVENSHTEIN FILTER] Removing rules with distance <= {max_distance}...")
    print("[WARNING] This operation can be slow for large datasets.")
    
    if not data:
        return data
    
    if len(data) > 5000:
        print(f"[WARNING] Large dataset ({len(data):,} rules). This may take a while.")
        response = input("Continue with Levenshtein filtering? (y/N): ").strip().lower()
        if response not in ['y', 'yes']:
            return data
    
    # Ask for distance threshold
    while True:
        try:
            distance_input = input(f"Enter maximum Levenshtein distance (1-10) [{max_distance}]: ").strip()
            if not distance_input:
                break
            max_distance = int(distance_input)
            if 1 <= max_distance <= 10:
                break
            else:
                print("Please enter a value between 1 and 10.")
        except ValueError:
            print("Please enter a valid number.")
    
    unique_rules = []
    removed_count = 0
    
    for i, (rule, count) in tqdm(enumerate(data), total=len(data), desc="Levenshtein filtering"):
        is_similar = False
        
        # Compare with already accepted rules
        for existing_rule, _ in unique_rules:
            if levenshtein_distance(rule, existing_rule) <= max_distance:
                is_similar = True
                removed_count += 1
                break
        
        if not is_similar:
            unique_rules.append((rule, count))
    
    print(f"[LEVENSHTEIN FILTER] Removed {removed_count:,} similar rules.")
    print(f"[LEVENSHTEIN FILTER] Final count: {len(unique_rules):,} unique rules.")
    
    return unique_rules

# ==============================================================================
# K. INTERACTIVE PROCESSING LOGIC
# ==============================================================================

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
        if next_target >= len(target_percentages): 
            break
            
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

def hashcat_rule_cleanup(data: List[Tuple[str, int]], mode: int = 1) -> List[Tuple[str, int]]:
    """Clean rules using hashcat's validation standards."""
    print(f"\n[HASHCAT CLEANUP] Starting rule validation for {'GPU' if mode == 2 else 'CPU'} compatibility...")
    cleaner = HashcatRuleCleaner(mode)
    cleaned_data = cleaner.clean_rules(data)
    return cleaned_data

def filter_by_min_occurrence(data: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Filter rules by minimum occurrence count."""
    if not data:
        return data
    max_count = data[0][1]
    suggested = max(1, sum(count for _, count in data) // 1000)
    
    while True:
        try:
            threshold = int(input(f"Enter MINIMUM occurrence count (1-{max_count:,}, suggested: {suggested:,}): "))
            if 1 <= threshold <= max_count:
                filtered = [(rule, count) for rule, count in data if count >= threshold]
                print(f"[FILTER] Kept {len(filtered):,} rules (min count: {threshold:,})")
                return filtered
            else:
                print(f"Please enter a value between 1 and {max_count:,}")
        except ValueError:
            print("Please enter a valid number.")

def filter_by_max_rules(data: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Filter rules by maximum number to keep."""
    if not data:
        return data
    max_possible = len(data)
    
    while True:
        try:
            limit = int(input(f"Enter MAXIMUM number of rules to keep (1-{max_possible:,}): "))
            if 1 <= limit <= max_possible:
                filtered = data[:limit]
                print(f"[FILTER] Kept top {len(filtered):,} rules")
                return filtered
            else:
                print(f"Please enter a value between 1 and {max_possible:,}")
        except ValueError:
            print("Please enter a valid number.")

def inverse_mode_filter(data: List[Tuple[str, int]]) -> List[Tuple[str, int]]:
    """Inverse mode - keep rules below a certain rank."""
    if not data:
        return data
    max_possible = len(data)
    
    while True:
        try:
            cutoff = int(input(f"Enter cutoff rank (rules BELOW this rank will be kept, 1-{max_possible:,}): "))
            if 1 <= cutoff <= max_possible:
                filtered = data[cutoff:]
                print(f"[INVERSE] Kept {len(filtered):,} rules below rank {cutoff:,}")
                return filtered
            else:
                print(f"Please enter a value between 1 and {max_possible:,}")
        except ValueError:
            print("Please enter a valid number.")

def save_rules_to_file(data: List[Tuple[str, int]], first_input_file: str):
    """Save current rules to file."""
    if not data:
        print("No rules to save!")
        return
        
    first_basename = os.path.basename(os.path.splitext(first_input_file)[0])
    output_file = f"{first_basename}_processed_{len(data)}rules.rule"
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for rule, count in data:
                f.write(f"{rule}\n")
        print(f"[SAVED] {len(data):,} rules saved to: {output_file}")
    except IOError as e:
        print(f"[ERROR] Failed to save file: {e}")

def interactive_processing_loop(sorted_data: List[Tuple[str, int]], total_lines: int, args: argparse.Namespace):
    """Main interactive processing loop after initial counting."""
    
    current_data = sorted_data
    unique_count = len(current_data)
    
    while True:
        print(f"\nCurrent dataset: {unique_count:,} unique rules")
        print("-" * 60)
        print("FILTERING OPTIONS:")
        print(" (1) Filter by MINIMUM OCCURRENCE")
        print(" (2) Filter by MAXIMUM NUMBER OF RULES (Statistical Cutoff - TOP N)")
        print(" (3) Filter by FUNCTIONAL REDUNDANCY (Logic Minimization) [RAM INTENSIVE]: rule")
        print(" (4) **INVERSE MODE** - Save rules *BELOW* the MAX_COUNT limit")
        if PYOPENCL_AVAILABLE and not args.no_gpu:
            print(" (5) **HASHCAT CLEANUP** - Validate and clean rules (CPU/GPU compatible)")
            print(" (6) **LEVENSHTEIN FILTER** - Remove similar rules (GPU-accelerated)")
        print(" (p) Show PARETO analysis")
        print(" (s) SAVE current rules to file")
        print(" (r) RESET to original dataset")
        print(" (q) QUIT program")
        print("-" * 60)
        
        choice = input("Enter your choice: ").strip().lower()
        
        if choice == 'q':
            print("\n[EXIT] Thank you for using the rule processor!")
            break
            
        elif choice == 'p':
            analyze_cumulative_value(current_data, total_lines)
            continue
            
        elif choice == 's':
            save_rules_to_file(current_data, args.input_files[0])
            continue
            
        elif choice == 'r':
            current_data = sorted_data
            unique_count = len(current_data)
            print(f"[RESET] Restored original dataset: {unique_count:,} rules")
            continue
            
        elif choice == '1':
            current_data = filter_by_min_occurrence(current_data)
            unique_count = len(current_data)
            
        elif choice == '2':
            current_data = filter_by_max_rules(current_data)
            unique_count = len(current_data)
            
        elif choice == '3':
            current_data = functional_minimization(current_data)
            unique_count = len(current_data)
            
        elif choice == '4':
            current_data = inverse_mode_filter(current_data)
            unique_count = len(current_data)
            
        elif choice == '5' and PYOPENCL_AVAILABLE and not args.no_gpu:
            # Ask for CPU or GPU compatibility
            print("\n[HASHCAT CLEANUP] Choose compatibility mode:")
            print(" (1) CPU compatibility (all rules allowed)")
            print(" (2) GPU compatibility (memory/reject rules disabled)")
            mode_choice = input("Enter mode (1 or 2): ").strip()
            mode = 1 if mode_choice == '1' else 2
            current_data = hashcat_rule_cleanup(current_data, mode)
            unique_count = len(current_data)
            
        elif choice == '6' and PYOPENCL_AVAILABLE and not args.no_gpu:
            current_data = levenshtein_filter(current_data, args.levenshtein_max_dist)
            unique_count = len(current_data)
            
        else:
            print("Invalid choice. Please try again.")
            continue
        
        # Show updated stats after each operation
        if choice in ['1', '2', '3', '4', '5', '6']:
            print(f"\n[STATUS] Dataset updated: {unique_count:,} unique rules")
            analyze_cumulative_value(current_data, total_lines)

def process_multiple_files(args: argparse.Namespace):
    
    # First, find all rule files recursively
    input_files = find_rule_files(args.input_files, max_depth=3)
    
    if not input_files:
        print("\n[ERROR] No rule files found to process!")
        return
    
    print("\n" + "="*60)
    print(f"STARTING MULTI-FILE PROCESSING")
    print(f"Found {len(input_files)} rule files")
    print(f"Processing Mode: {'DISK' if args.use_disk else 'RAM'}")
    print(f"GPU Available: {'YES' if PYOPENCL_AVAILABLE and not args.no_gpu else 'NO'}")
    print(f"Levenshtein Filter Max Dist: {args.levenshtein_max_dist}")
    print("="*60)
    
    # Determine processing method
    processing_method = "AUTO"
    if args.no_gpu:
        processing_method = "CPU"
        print("[INFO] GPU disabled by user, using CPU processing")
    else:
        # For very large datasets, ask user for preference
        if PYOPENCL_AVAILABLE:
            # Estimate total rules by reading first file
            try:
                with open(input_files[0], 'r', encoding='latin-1', errors='ignore') as f:
                    sample_lines = sum(1 for _ in f)
                estimated_total = sample_lines * len(input_files)
                
                if estimated_total > 100000:  # Only ask for large datasets
                    processing_method = ask_processing_method(estimated_total)
                else:
                    print(f"[INFO] Small dataset estimated ({estimated_total:,} rules), using auto-selection")
            except:
                print("[INFO] Could not estimate dataset size, using auto-selection")
    
    # 1. Reading, Combining, Counting, and Sorting Data 
    if args.use_disk:
        sorted_data_textual, total_lines = process_disk_data(input_files, processing_method)
    else:
        sorted_data_textual, total_lines = process_ram_data(input_files, processing_method)
    
    if total_lines == 0 or not sorted_data_textual:
        print("\nNo valid data to process. Exiting.")
        return

    # 2. Post-processing Stats and Analysis (Textual)
    unique_count_textual = len(sorted_data_textual)
    
    if total_lines > 0:
        unique_percentage = (unique_count_textual / total_lines) * 100
        redundant_lines = total_lines - unique_count_textual
        redundant_percentage = (redundant_lines / total_lines) * 100
    else:
        unique_percentage = 0.0
        redundant_lines = 0
        redundant_percentage = 0.0

    print(f"\nThe consolidated dataset contains {unique_count_textual:,} TEXTUALLY unique entries.")
    print(f"[STAT] Unique entries are {unique_percentage:.2f}% of the total lines read.")
    print(f"[STAT] Redundant lines (duplicates) removed: {redundant_lines:,} ({redundant_percentage:.2f}%)")
    
    # Show Pareto analysis immediately after counting
    analyze_cumulative_value(sorted_data_textual, total_lines)
    
    # Continue with interactive menu for further processing
    interactive_processing_loop(sorted_data_textual, total_lines, args)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('input_files', nargs='+', 
                       help='Paths to the debug hashcat rule files or directories to process recursively.')
    parser.add_argument('-d', '--use-disk', action='store_true', 
                       help='Use disk (temp files) for initial consolidation to save RAM.')
    parser.add_argument('-ld', '--levenshtein-max-dist', type=int, default=0, 
                       help='Maximum Levenshtein distance for similarity filtering (0 = disabled).')
    parser.add_argument('-o', '--output-stdout', action='store_true', 
                       help='Output the result to STDOUT for piping.')
    parser.add_argument('--no-gpu', action='store_true', 
                       help='Disable GPU acceleration for rule counting.')
    
    args = parser.parse_args()
    process_multiple_files(args)
