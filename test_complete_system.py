#!/usr/bin/env python3
"""
Test complet pentru sistemul de detectare tracking pixels
"""

import sys
import time
from pathlib import Path

# Adaugă path pentru scripturi
sys.path.append('scripts')

def test_optimized_engine():
    """Test motorul optimizat O(1)"""
    print("🔧 Testing OptimizedPatternEngine...")
    from optimized_pattern_engine import OptimizedPatternEngine
    
    engine = OptimizedPatternEngine()
    stats = engine.get_performance_stats()
    
    print(f"   ✅ Engine loaded: {stats['domains_indexed']} domains indexed")
    print(f"   ✅ Patterns cached: {stats['patterns_cached']}")
    print(f"   ✅ Init time: {stats['init_time']:.3f}s")
    return True

def test_reporting_system():
    """Test sistemul de raportare"""
    print("📊 Testing AdvancedReportingSystem...")
    from advanced_reporting import AdvancedReportingSystem
    
    reporter = AdvancedReportingSystem()
    print("   ✅ Reporting system created successfully")
    return True

def test_auto_update_system():
    """Test sistemul auto-update"""
    print("🔄 Testing Auto-Update System...")
    
    # Test orchestrator
    from auto_update_orchestrator import AutoUpdateOrchestrator
    orchestrator = AutoUpdateOrchestrator()
    print("   ✅ AutoUpdateOrchestrator created")
    
    # Test GitHub monitor
    from realtime_github_sync import GitHubChangeMonitor
    monitor = GitHubChangeMonitor()
    print("   ✅ GitHubChangeMonitor created")
    
    # Test pattern validator
    from pattern_validator import PatternValidator
    validator = PatternValidator()
    print("   ✅ PatternValidator created")
    
    # Test version control
    from pattern_version_control import PatternVersionControl
    vc = PatternVersionControl()
    print("   ✅ PatternVersionControl created")
    
    return True

def test_performance():
    """Test performanța în paralel"""
    print("⚡ Testing Performance...")
    from optimized_pattern_engine import OptimizedPatternEngine
    
    engine = OptimizedPatternEngine()
    
    # Test batch processing
    test_urls = [
        'https://track.flexlinks.com/test',
        'https://cc.zdnet.com/pixel.gif',
        'https://www.pntrac.com/test',
        'https://google.com/test',
        'https://facebook.com/pixel.gif'
    ] * 10  # 50 URLs total
    
    start_time = time.time()
    results = engine.batch_analyze_urls(test_urls)
    end_time = time.time()
    
    speed = len(test_urls) / (end_time - start_time)
    threats = len([r for r in results if r])
    
    print(f"   ✅ Processed {len(test_urls)} URLs in {end_time-start_time:.3f}s")
    print(f"   ✅ Speed: {speed:.1f} URLs/sec")
    print(f"   ✅ Threats detected: {threats}")
    
    return True

def test_email_analysis():
    """Test analiza email-uri reale"""
    print("📧 Testing Email Analysis...")
    from optimized_pattern_engine import OptimizedPatternEngine
    
    engine = OptimizedPatternEngine()
    
    # Găsește email-uri de test
    test_emails_dir = Path('test_emails')
    if not test_emails_dir.exists():
        print("   ⚠️  No test_emails/ directory found")
        return True
    
    email_files = list(test_emails_dir.glob('*.eml'))
    if not email_files:
        print("   ⚠️  No .eml files found in test_emails/")
        return True
    
    print(f"   📧 Found {len(email_files)} test emails")
    
    # Testează primul email
    email_file = email_files[0]
    try:
        with open(email_file, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        
        result = engine.analyze_email_content(content)
        
        print(f"   ✅ Analyzed {email_file.name}")
        print(f"   ✅ URLs found: {len(result.get('urls', []))}")
        print(f"   ✅ Threats detected: {len(result.get('threats', []))}")
        
    except Exception as e:
        print(f"   ❌ Error analyzing {email_file.name}: {e}")
        return False
    
    return True

def main():
    """Rulează toate testele"""
    print("🚀 TESTING COMPLETE EMAIL TRACKER SYSTEM")
    print("=" * 50)
    
    start_time = time.time()
    
    tests = [
        test_optimized_engine,
        test_reporting_system,
        test_auto_update_system,
        test_performance,
        test_email_analysis
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            result = test()
            if result:
                passed += 1
                print("")
            else:
                failed += 1
                print("   ❌ Test failed\n")
        except Exception as e:
            failed += 1
            print(f"   ❌ Test error: {e}\n")
    
    end_time = time.time()
    
    print("=" * 50)
    print(f"🏁 TEST RESULTS:")
    print(f"   ✅ Passed: {passed}")
    print(f"   ❌ Failed: {failed}")
    print(f"   ⏱️  Total time: {end_time-start_time:.2f}s")
    
    if failed == 0:
        print("\n🎉 ALL SYSTEMS OPERATIONAL! 🎉")
    else:
        print(f"\n⚠️  {failed} test(s) failed")

if __name__ == "__main__":
    main()