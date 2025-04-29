import time
import bisect
import re
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict

# Load file into memory
def load_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return [line.strip() for line in f.readlines() if line.strip()]

# Linear Search
def linear_search(lines, query):
    return query in lines

# Binary Search (requires sorted list)
def binary_search(sorted_lines, query):
    index = bisect.bisect_left(sorted_lines, query)
    return index < len(sorted_lines) and sorted_lines[index] == query

# Hash Set Lookup
def hash_set_search(hash_set, query):
    return query in hash_set

# Regex Search
def regex_search(lines, query):
    pattern = re.compile(re.escape(query))
    return any(pattern.search(line) for line in lines)

# Rabin-Karp Algorithm
def rabin_karp_search(lines, query, base=256, mod=101):
    query_len = len(query)
    query_hash = sum(ord(query[i]) * (base ** (query_len - i - 1)) for i in range(query_len)) % mod
    
    for line in lines:
        if len(line) < query_len:
            continue
        line_hash = sum(ord(line[i]) * (base ** (query_len - i - 1)) for i in range(query_len)) % mod
        if line_hash == query_hash and line[:query_len] == query:
            return True
    return False

# Knuth-Morris-Pratt (KMP) Algorithm
def kmp_search(lines, query):
    def build_lps(pattern):
        lps = [0] * len(pattern)
        j = 0
        for i in range(1, len(pattern)):
            while j > 0 and pattern[i] != pattern[j]:
                j = lps[j - 1]
            if pattern[i] == pattern[j]:
                j += 1
                lps[i] = j
        return lps
    
    lps = build_lps(query)
    
    for line in lines:
        j = 0
        for i in range(len(line)):
            while j > 0 and line[i] != query[j]:
                j = lps[j - 1]
            if line[i] == query[j]:
                j += 1
            if j == len(query):
                return True
    return False

# Function to benchmark search methods
def benchmark_search_methods(filepath, query, reread_on_query):
    if not reread_on_query:
        lines = load_file(filepath)
        sorted_lines = sorted(lines)
        hash_set = set(lines)

    methods = {
        "Linear Search": lambda: linear_search(lines, query),
        "Binary Search": lambda: binary_search(sorted_lines, query),
        "Hash Set Lookup": lambda: hash_set_search(hash_set, query),
        "Regex Search": lambda: regex_search(lines, query),
        "Rabin-Karp Search": lambda: rabin_karp_search(lines, query),
        "Knuth-Morris-Pratt (KMP) Search": lambda: kmp_search(lines, query)
    }

    results = []
    for method, func in methods.items():
        if reread_on_query:
            lines = load_file(filepath)
            sorted_lines = sorted(lines)
            hash_set = set(lines)

        start = time.time()
        found = func()
        end = time.time()
        results.append((method, found, end - start))
    
    return results

# File paths for testing
file_paths = {
    "Small (15k+)": "data/200k.txt",
    "Medium (150k+)": "data/350k.txt",
    "Large (1M+)": "data/900k.txt"
}

# Sample query
query = "TRUST"

# Toggle reread_on_query (True = reload file for each search, False = load once)
reread_on_query = False

# Store results
all_results = []

for size, path in file_paths.items():
    print(f"\n Testing file: {size} ({path})")
    results = benchmark_search_methods(path, query, reread_on_query)
    
    for method, found, duration in results:
        all_results.append((size, method, found, duration))
        print(f"{method}: Found={found}, Time={duration:.6f} sec")

# Convert results to DataFrame
df = pd.DataFrame(all_results, columns=["File Size", "Algorithm", "Found", "Time (s)"])

# Save results to CSV
df.to_csv("search_results.csv", index=False)
print("\nResults saved to search_results.csv")

# Generate bar chart for performance comparison
plt.figure(figsize=(12, 7))
avg_times = df.groupby("Algorithm")["Time (s)"].mean().sort_values()
plt.barh(avg_times.index, avg_times.values, color="blue")
plt.xlabel("Average Execution Time (seconds)")
plt.ylabel("Search Algorithms")
plt.title("Performance Comparison of Search Algorithms - Reread_on_query(False)")
plt.grid(axis="x", linestyle="--", alpha=0.7) 
plt.savefig("algorithm_bench.png", dpi=300)
plt.show()

# Display performance table
print("\nPerformance Table Reread_on_query(False):")
print(df.pivot(index="Algorithm", columns="File Size", values="Time (s)"))

# Plot Performance Comparison
plt.figure(figsize=(12, 6))

styles = {
    "Linear Search": {"color": "blue", "marker": "o"},
    "Binary Search": {"color": "orange", "marker": "s"},
    "Hash Set Lookup": {"color": "limegreen", "marker": "d"},
    "Regex Search": {"color": "purple", "marker": "^"},
    "Rabin-Karp Search": {"color": "brown", "marker": "v"},
    "Knuth-Morris-Pratt (KMP) Search": {"color": "pink", "marker": "p"}
}

for algo in df["Algorithm"].unique():
    subset = df[df["Algorithm"] == algo]
    plt.plot(subset["File Size"], subset["Time (s)"], linestyle="-", linewidth=2, marker=styles[algo]["marker"], label=algo, color=styles[algo]["color"])

plt.xlabel("File Size")
plt.ylabel("Time (seconds)")
plt.title("Algorithm Performance Comparison - Reread_on_query(False)")
plt.xticks(rotation=45)
plt.legend()
plt.grid()
plt.show()
