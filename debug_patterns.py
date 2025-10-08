#!/usr/bin/env python3

from scripts.optimized_threat_intelligence import OptimizedThreatIntelligence
import json

print("Testing pattern loading...")

ti = OptimizedThreatIntelligence()
ti.load_optimized_sources()  # Load patterns first!

print(f'Total tracking patterns loaded: {len(ti.tracking_patterns)}')
print('First 3 tracking patterns:')
for i, pattern in enumerate(ti.tracking_patterns[:3]):
    print(f'  {i+1}. {pattern}')

print(f'\nPhishing domains loaded: {len(ti.phishing_domains)}')
print(f'Malware domains loaded: {len(ti.malware_domains)}')
print(f'Suspicious services loaded: {len(ti.suspicious_services)}')

# Test actual email analysis
print("\n" + "="*50)
print("TESTING ACTUAL EMAIL ANALYSIS")
print("="*50)

from scripts.final_pixel_detector import FinalPixelDetector

detector = FinalPixelDetector()
result = detector.analyze_email_file("test_emails/spyware_malware.eml")

print(f"Analysis result summary:")
print(f"- Tracking pixels detected: {result.get('tracking_pixels_detected', 0)}")
print(f"- CSS pixels detected: {result.get('css_pixels_detected', 0)}")
print(f"- Suspicious domains: {result.get('suspicious_domains_detected', 0)}")
print(f"- Phishing indicators: {result.get('phishing_indicators', 0)}")
print(f"- Risk level: {result.get('risk_assessment', {}).get('level', 'Unknown')}")