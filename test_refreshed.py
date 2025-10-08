#!/usr/bin/env python3

from scripts.final_pixel_detector import FinalPixelDetector
import json

print("Testing with refreshed cache...")

detector = FinalPixelDetector()
result = detector.analyze_email_file('test_emails/spyware_malware.eml')

print("\n" + "="*50)
print("DETECTION RESULTS WITH REFRESHED CACHE")
print("="*50)
print(f"- Tracking pixels: {result.get('tracking_pixels_detected', 0)}")
print(f"- CSS pixels: {result.get('css_pixels_detected', 0)}")
print(f"- Suspicious domains: {result.get('suspicious_domains_detected', 0)}")

if isinstance(result, dict):
    print(f"- Risk level: {result.get('risk_assessment', {}).get('level', 'Unknown')}")
    
    # Show more details
    if 'tracking_pixels' in result:
        print(f"\nTracking pixels found: {len(result['tracking_pixels'])}")
        for i, pixel in enumerate(result['tracking_pixels'][:3]):
            print(f"  {i+1}. {pixel}")
    
    if 'css_pixels' in result:
        print(f"\nCSS pixels found: {len(result['css_pixels'])}")
        for i, pixel in enumerate(result['css_pixels'][:3]):
            print(f"  {i+1}. {pixel}")
else:
    print("Result is not a dictionary, showing raw result:")
    print(result)