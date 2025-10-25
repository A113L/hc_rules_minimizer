**Hashcat Rule Consolidation and Minimization Tool**

This Python tool is designed for optimizing and minimizing large sets of Hashcat rules generated in --debug-mode=1. Its primary goal is the drastic reduction of redundancy within rule files while maintaining or improving the crack rate metric (CR/s).

*Key Features and Value*

1. Textual and Statistical Consolidation
The tool processes multiple input files simultaneously, eliminating textual duplicates and presenting detailed statistics on the removed redundancy (e.g., over 85% reduction in typical datasets). All unique rules are then sorted in descending order based on their frequency of occurrence in the debug set, a key indicator of their value.

2. Logical Minimization (Functional Redundancy)
By utilizing a built-in, simplified Hashcat rule simulation engine (RuleEngine), the script can identify rules that, despite different syntax, yield the same final outcome on a defined test vector (e.g., $1 vs. D0 i01 $1). Only one rule (the most frequent/most important) is selected from each group of logically equivalent rules, resulting in further reduction without loss of functionality.

3. Flexible Filtering and Statistical Pruning
The user retains full control over the final minimization by selecting one of three filtering modes:

**Mode 1** (MIN_COUNT): Saves only rules (or functional groups) whose occurrence count exceeds a defined threshold (e.g., appeared at least 100 times).

**Mode 2** (MAX_COUNT / Statistical Pruning): Saves only the Top N rules (or functional groups) from the sorted list (e.g., saves the 50,000 most effective rules).

**Mode 3** (FUNCTIONAL): Applies Logical Minimization first, followed by additional Statistical Pruning.

**Mode 4** (INVERSE): (The 'Leftovers' mode). It's designed to save the less frequent rules while intentionally skipping the most common and potent ones.

*How Mode 4 Works*

Mode 4 executes the opposite of standard filtering:

1. User Input: You define a number (N) of top rules to SKIP.

2. Skipping: The script discards the first N most valuable rules (those with the highest total occurrence count).

3. Saving: It writes all rules that follow N to the output file.

*Purpose*

1. Its main use is in a two-phase cracking strategy:

2. Phase 1 uses the TOP N rules (from Mode 2) for a quick attack.

3. Phase 2 uses the Mode 4 (Inverse) rules to perform a slower, more exhaustive attack on the remaining hashes, ensuring no time is wasted re-testing the rules used in Phase 1.

**PARETO - SUGGESTED CUTOFF LIMITS** is performing a Cumulative Value Analysis on your sorted rule data. This analysis identifies the point where a small fraction of the rules accounts for a large percentage of the total rule occurrences (i.e., potential cracked hashes).

1. Suggest Cutoff: The number of rules required to reach the 90% or 95% threshold is provided as the suggested cutoff limit. These limits represent the smallest set of rules that provide the maximum cracking value, aligning with the 80/20 Pareto principle.

2. The final suggested number (the "MAX_COUNT") is what you would use in Mode 2 to build your efficient, first-phase attack file.

**The new flag** *-ld N* or *--levenshtein-max-dist N*

1. N=1	Rules differ by only 1 operation (e.g., insertion, deletion, or substitution).	Conservative. Removes only extremely obvious duplicates and close typos. The final set remains large.
2. N=2	Rules differ by up to 2 operations.	Recommended Compromise. Provides significant size reduction by eliminating near-variants (e.g., T2t vs. T3t or D0 vs. D1).
3. N=3	Rules differ by up to 3 operations.	Aggressive. Useful for massive rule sets (hundreds of thousands) where maximum time-saving is needed. May remove slightly more diverse rules.

*Value for the User*

This tool transforms large, chaotic rule sets into compact, highly effective, and optimized files that are faster to load and more efficient in attacks on large, modern GPU-based platforms. This capability enables the creation of professional, custom rules that surpass publicly available sets in terms of performance and precision.

**Credits**

https://github.com/mkb2091/PyRuleEngine
