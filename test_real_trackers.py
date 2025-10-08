#!/usr/bin/env python3

from scripts.final_pixel_detector import FinalPixelDetector
import json

print("Testing REAL TRACKER EMAIL...")

detector = FinalPixelDetector()
result = detector.analyze_email_file('test_emails/real_trackers.eml')

print("="*50)
print("REAL TRACKER DETECTION RESULTS")
print("="*50)
print(f"Total pixels found: {result.get('pixels_found', 0)}")
print(f"HTML pixels: {result.get('html_pixels', 0)}")
print(f"CSS pixels: {result.get('css_pixels', 0)}")
print(f"Malicious pixels: {result.get('malicious_pixels', 0)}")
print(f"Threat score: {result.get('total_threat_score', 0)}")
print(f"Risk assessment: {result.get('risk_assessment', 'Unknown')}")

if result.get('pixels'):
    print(f"\nPixel details ({len(result['pixels'])}):")
    for i, pixel in enumerate(result['pixels'][:5]):
        print(f"  {i+1}. {pixel}")
else:
    print("\nNo pixels detected")

# Let's also check what's in the email itself
print("\n" + "="*50)
print("EMAIL CONTENT ANALYSIS")
print("="*50)

try:
    with open('test_emails/real_trackers.eml', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Look for obvious tracking patterns
    tracking_indicators = ['tracking', 'pixel', 'beacon', 'open', 'click', 'track', 'analytics']
    
    for indicator in tracking_indicators:
        count = content.lower().count(indicator)
        if count > 0:
            print(f"'{indicator}' appears {count} times in email")
    
    # Look for image tags
    import re
    img_tags = re.findall(r'<img[^>]*>', content, re.IGNORECASE)
    print(f"\nImage tags found: {len(img_tags)}")
    for i, img in enumerate(img_tags[:3]):
        print(f"  {i+1}. {img}")
        
except Exception as e:
    print(f"Error reading email: {e}")