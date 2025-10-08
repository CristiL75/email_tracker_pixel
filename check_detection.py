#!/usr/bin/env python3

import json

print("Checking if tracking domains are in our cache...")
domains_to_check = ['track.flexlinks.com', 'cc.zdnet.com', 'www.pntrac.com']

# Check mailtracker cache
with open('cache/mailtracker_cache.json', 'r') as f:
    mailtracker = json.load(f)

print(f"MailTracker cache has {len(mailtracker['data'])} items")

for domain in domains_to_check:
    found = False
    for item in mailtracker['data']:
        if domain in item.get('domain', '') or domain in item.get('pattern', ''):
            print(f"✓ {domain} FOUND in MailTracker: {item['pattern']}")
            found = True
            break
    if not found:
        print(f"✗ {domain} NOT found in MailTracker")

print("\n" + "="*50)
print("CHECKING DETECTION LOGIC")
print("="*50)

# Test detection logic manually
from scripts.final_pixel_detector import FinalPixelDetector

detector = FinalPixelDetector()

# Test individual URLs
test_urls = [
    "https://track.flexlinks.com/a.ashx?tc=123456&id=user123",
    "https://cc.zdnet.com/v1/otc/pixel.gif?campaign=newsletter", 
    "https://www.pntrac.com/t/track?id=campaign123"
]

print("Testing individual URLs against detection logic:")
for url in test_urls:
    # Check against mailtracker patterns
    threat_score = 0
    for pattern_data in mailtracker['data']:
        pattern = pattern_data.get('pattern', '')
        # Convert pattern to regex-like matching
        if '*' in pattern:
            import re
            regex_pattern = pattern.replace('*', '.*').replace('?', r'\?')
            if re.search(regex_pattern, url):
                threat_score += 1
                print(f"  ✓ {url} matches pattern: {pattern}")
                break
    
    if threat_score == 0:
        print(f"  ✗ {url} - NO MATCH found")