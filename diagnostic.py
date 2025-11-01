import pandas as pd
import numpy as np

# Load training data
data = pd.read_csv("datasets/Phishing_Websites_Data.csv")

print("="*70)
print("ANALYZING TRAINING DATA ENCODING")
print("="*70)

# Separate phishing vs legitimate
phishing = data[data['Result'] == 1]
legitimate = data[data['Result'] == -1]

print(f"\nDataset: {len(data)} samples")
print(f"  Phishing: {len(phishing)} ({len(phishing)/len(data)*100:.1f}%)")
print(f"  Legitimate: {len(legitimate)} ({len(legitimate)/len(data)*100:.1f}%)")

# Analyze key features
features_to_check = [
    'having_IP_Address',
    'URL_Length', 
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'having_Sub_Domain',
    'SSLfinal_State',
    'URL_of_Anchor',
    'Request_URL',
    'Links_in_tags',
    'SFH',
]

print("\n" + "="*70)
print("FEATURE ENCODING ANALYSIS")
print("="*70)

for feat in features_to_check:
    if feat not in data.columns:
        continue
    
    print(f"\n{feat}:")
    print("-" * 70)
    
    # Overall distribution
    overall = data[feat].value_counts().sort_index()
    print(f"Overall distribution: {dict(overall)}")
    
    # Distribution in phishing vs legitimate
    phish_dist = phishing[feat].value_counts(normalize=True).sort_index() * 100
    legit_dist = legitimate[feat].value_counts(normalize=True).sort_index() * 100
    
    print(f"\nPhishing URLs:")
    for val, pct in phish_dist.items():
        print(f"  Value {val:2d}: {pct:5.1f}%")
    
    print(f"\nLegitimate URLs:")  
    for val, pct in legit_dist.items():
        print(f"  Value {val:2d}: {pct:5.1f}%")
    
    # Determine what each value means
    print(f"\nInterpretation:")
    if len(phish_dist) > 0 and len(legit_dist) > 0:
        # Find which value is most common in phishing
        phish_mode = phish_dist.idxmax()
        legit_mode = legit_dist.idxmax()
        
        if phish_mode == legit_mode:
            print(f"  ⚠️  Value {phish_mode} is most common in BOTH classes")
        else:
            print(f"  ✓ Value {phish_mode} → Likely PHISHING indicator")
            print(f"  ✓ Value {legit_mode} → Likely LEGITIMATE indicator")

# Check for suspicious patterns
print("\n" + "="*70)
print("SUSPICIOUS PATTERNS IN TRAINING DATA")
print("="*70)

# Features that are mostly one value
for feat in data.columns:
    if feat == 'Result':
        continue
    
    value_counts = data[feat].value_counts()
    if len(value_counts) > 0:
        most_common_pct = value_counts.iloc[0] / len(data) * 100
        
        if most_common_pct > 80:
            most_common_val = value_counts.index[0]
            print(f"\n⚠️  {feat}:")
            print(f"    {most_common_pct:.1f}% of samples have value {most_common_val}")
            print(f"    This feature may not be discriminative!")

# Generate corrected feature logic
print("\n" + "="*70)
print("RECOMMENDED FEATURE LOGIC")
print("="*70)

print("""
Based on the analysis above, update your features.py with the correct logic.

For each feature, use this pattern:

def feature_name(url):
    # Extract the actual property
    condition = check_something(url)
    
    # Return based on what training data shows:
    # - If phishing URLs mostly have value 1 for this feature → return 1 when condition is true
    # - If legitimate URLs mostly have value 1 → return 1 when condition is false
    # - If feature is ambiguous → return 0
    
    if condition:
        return 1  # or -1, based on training data
    else:
        return -1  # or 1, based on training data
""")

print("\nExample corrections needed:")
print("  • If 'having_At_Symbol' = 1 in 85% of samples (both classes),")
print("    then maybe the dataset uses 1 = 'no @ symbol' (inverted logic)")
print("  • Check if your feature extraction logic is inverted!")