🔬 **ruleminimizer.py: Advanced Hashcat Rule Minimization & Analysis**

ruleminimizer.py is an all-in-one utility for managing massive Hashcat rule files. Unlike simple de-duplication tools, this script employs a full, simulated Hashcat rule engine and advanced statistical methods (including Functional Minimization and Levenshtein Distance filtering) to reduce your rule sets based on logic and statistical value, not just textual uniqueness.

It is designed for large-scale operations, offering an optional disk-based consolidation mode (-d) to process multi-gigabyte rule sets that cannot fit entirely into RAM.

✨ **Features**

1. Minimization Modes (Interactive Selection)

**The script provides four primary interactive modes for filtering your consolidated rule set:**

**Textual Uniqueness**

- Saves all unique rules after removing comments and duplicates.
- Basic cleanup and de-duplication.

**Minimum Occurrence**

- Filters rules that appear fewer than a specified $N$ times.

- Removes statistically insignificant noise.

**Statistical Cutoff (Top N)**

- Saves only the top $N$ most frequently occurring rules.
- Creates highly optimized, small rule files for primary attacks.

**Functional Minimization**

- Uses a Hashcat rule engine simulation on a test vector to group rules that produce the exact same output. It keeps only the most frequent rule from each functional group.
- Eliminates logic redundancy (e.g., l and u on an all-lowercase word are functionally redundant). RAM Intensive.

**Inverse Mode**

- Saves rules that are below the Top N cutoff limit (the "Leftovers").
- Creates secondary, targeted rule sets for dual-phase attacks.

**Advanced Filters & Analysis**

1. Levenshtein Distance Filtering (-ld): Reduces semantic redundancy. If a less frequent rule is too similar (distance $\le$ N) to an already-kept, higher-frequency rule, it is discarded.

2. Pareto Analysis: After consolidation, the script suggests cutoff limits by showing how many rules are needed to account for 50%, 80%, 90%, and 95% of the total rule occurrences.

3. Multiprocessing: Uses tqdm and multiprocessing for fast, efficient Functional Minimization (Mode 3).

4. Disk Mode (-d): Uses temporary disk files for consolidation, allowing you to process large rule sets without consuming excessive RAM.

5. STDOUT Output (-o): Enables piping results directly into other command-line tools.

🚀 **Usage**

*Prerequisites*

- Python 3.x

- tqdm: For progress bars (pip install tqdm)

- NumPy (Optional): Highly recommended for faster Levenshtein distance calculations (pip install numpy)

**Basic Execution & Filtering**

The script takes one or more rule files as positional arguments and runs interactively.

*Consolidate and get the top 100,000 unique rules (Mode 2):*

- Run the script and choose '2' at the prompt, then enter '100000'.
```python3 rules_processor.py ruleset1.rule ruleset2.rule```


*Functional Minimization (Mode 3) with Levenshtein Filter:*

This command applies the Levenshtein filter first, then groups the remaining rules by their functional signature, keeping the most frequent rule from each group.

```python3 rules_processor.py giant_debug.rule -ld 2```

*[Interactive Prompts Follow]*
- At prompt 1: Choose '3' (Functional Minimization).
- At prompt 2: Choose '2' (Statistical Cutoff) and enter your desired limit (e.g., 50000).


*Output to STDOUT (Piping):*

Use the --output-stdout flag to pipe the result directly to another utility for streamlined command-line pipelines.

```python3 rules_processor.py rules/big_file.rule --output-stdout | head -n 50000 > top_50k_functional.rule```

Note: All informational and error messages are printed to STDERR, ensuring only the final rules are sent to STDOUT.


*Process Huge Files using Disk Mode:*

If you have insufficient RAM for consolidation, use the -d flag. The initial counting and sorting phase will use a temporary file on disk.

```python3 rules_processor.py rule_dump_1.rule rule_dump_2.rule -d```

```# python3 ruleminimizer.py -h
[INFO] NumPy found. Using optimized Levenshtein distance calculation.
usage: ruleminimizer.py [-h] [-d] [-ld LEVENSHTEIN_MAX_DIST] [-o] input_files [input_files ...]

The script is used to process debugged hashcat rules from files.
Features:
- Full Hashcat Rule Engine simulation for Functional Minimization (Mode 3).
- Multiprocessing (tqdm) for fast Functional Minimization.
- Optional disk usage for initial consolidation of huge files (--use-disk).
- Statistical Cutoff (Mode 2) and Inverse Mode (Mode 4) for dual-phase attacks.
- Pareto Analysis (Cumulative Value) for suggesting cutoff limits.
- Levenshtein Distance Filtering for Semantic Redundancy Removal, optimized with NumPy (optional).
- NEW: Option to output results to STDOUT for piping (-o / --output-stdout).

positional arguments:
  input_files           Paths to the debug hashcat rule files to process.

options:
  -h, --help            show this help message and exit
  -d, --use-disk        Use disk (temp files) for initial consolidation to save RAM.
  -ld LEVENSHTEIN_MAX_DIST, --levenshtein-max-dist LEVENSHTEIN_MAX_DIST
                        Filters rules based on Levenshtein distance. Rules too close (<= DIST) to a better-ranked rule are removed. 0 = disabled (Default).
  -o, --output-stdout   Output the result to standard output (STDOUT) instead of creating a file. Informational messages are sent to STDERR.
```

https://hcrt.pages.dev/ruleminimizer.static_workflow
