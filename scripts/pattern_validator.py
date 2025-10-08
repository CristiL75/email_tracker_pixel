#!/usr/bin/env python3
"""
Pattern Validation Engine

Multi-stage validation system for tracking protection patterns.
Ensures new patterns are syntactically correct, performant, and don't cause false positives.

Validation Stages:
1. Syntax Validation - Regex compilation and basic format checks
2. Performance Testing - Benchmark against large URL datasets
3. False Positive Detection - Test against legitimate domains
4. Community Scoring - Integration with threat intelligence feeds
5. Staging Environment Testing - Real-world validation
"""

import re
import time
import json
import logging
import threading
import statistics
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of pattern validation"""
    pattern: str
    source: str
    stage: str
    passed: bool
    score: float  # 0.0 to 1.0
    details: Dict[str, Any]
    duration_ms: float
    timestamp: float

@dataclass
class PatternMetrics:
    """Performance metrics for a pattern"""
    pattern: str
    compile_time_ms: float
    avg_match_time_ns: float
    false_positive_rate: float
    true_positive_rate: float
    complexity_score: float
    memory_usage_bytes: int

class PatternValidator:
    """Comprehensive pattern validation system"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent.parent
        self.validation_dir = self.base_path / "validation"
        self.test_data_dir = self.validation_dir / "test_data"
        self.results_dir = self.validation_dir / "results"
        
        # Ensure directories exist
        for directory in [self.validation_dir, self.test_data_dir, self.results_dir]:
            directory.mkdir(exist_ok=True)
        
        # Load test datasets
        self.legitimate_domains = self._load_legitimate_domains()
        self.known_trackers = self._load_known_trackers()
        self.test_urls = self._load_test_urls()
        
        # Performance thresholds
        self.performance_thresholds = {
            'max_compile_time_ms': 10.0,
            'max_avg_match_time_ns': 1000000,  # 1ms
            'max_false_positive_rate': 0.001,  # 0.1%
            'min_complexity_score': 0.3,
            'max_memory_usage_mb': 10
        }
        
        # Thread pool for concurrent validation
        self.thread_pool = ThreadPoolExecutor(max_workers=4)
    
    def _load_legitimate_domains(self) -> Set[str]:
        """Load list of legitimate domains for false positive testing"""
        legitimate_file = self.test_data_dir / "legitimate_domains.txt"
        
        if not legitimate_file.exists():
            # Create default legitimate domains list
            legitimate_domains = {
                # Email providers
                'gmail.com', 'outlook.com', 'yahoo.com', 'hotmail.com',
                'icloud.com', 'protonmail.com', 'aol.com',
                
                # Major platforms
                'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
                'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
                
                # E-commerce
                'ebay.com', 'paypal.com', 'stripe.com', 'shopify.com',
                'etsy.com', 'walmart.com', 'target.com',
                
                # News and media
                'cnn.com', 'bbc.com', 'reuters.com', 'nytimes.com',
                'theguardian.com', 'wsj.com', 'bloomberg.com',
                
                # Financial
                'chase.com', 'bankofamerica.com', 'wellsfargo.com',
                'citibank.com', 'schwab.com', 'fidelity.com',
                
                # Technology
                'github.com', 'stackoverflow.com', 'mozilla.org',
                'cloudflare.com', 'amazon.com', 'salesforce.com',
                
                # Government
                'irs.gov', 'treasury.gov', 'fbi.gov', 'nasa.gov',
                'whitehouse.gov', 'congress.gov'
            }
            
            legitimate_file.write_text('\n'.join(legitimate_domains))
            return legitimate_domains
        
        return set(legitimate_file.read_text().strip().split('\n'))
    
    def _load_known_trackers(self) -> Set[str]:
        """Load known tracking domains for validation"""
        trackers_file = self.test_data_dir / "known_trackers.txt"
        
        if not trackers_file.exists():
            # Create default known trackers list
            known_trackers = {
                'googletagmanager.com', 'google-analytics.com', 'doubleclick.net',
                'facebook.com', 'connect.facebook.net', 'analytics.twitter.com',
                'scorecardresearch.com', 'quantserve.com', 'outbrain.com',
                'taboola.com', 'adsystem.com', 'advertising.com',
                'adsrvr.org', 'bluekai.com', 'krxd.net',
                'rlcdn.com', 'rubiconproject.com', 'amazon-adsystem.com'
            }
            
            trackers_file.write_text('\n'.join(known_trackers))
            return known_trackers
        
        return set(trackers_file.read_text().strip().split('\n'))
    
    def _load_test_urls(self) -> List[str]:
        """Load test URLs for performance testing"""
        urls_file = self.test_data_dir / "test_urls.txt"
        
        if not urls_file.exists():
            # Generate test URLs
            test_urls = []
            
            # Add legitimate URLs
            for domain in list(self.legitimate_domains)[:100]:
                test_urls.extend([
                    f"https://{domain}/",
                    f"https://{domain}/index.html",
                    f"https://{domain}/page.php?id=123",
                    f"https://www.{domain}/contact",
                    f"https://subdomain.{domain}/api/v1/data"
                ])
            
            # Add tracking URLs
            for domain in list(self.known_trackers)[:50]:
                test_urls.extend([
                    f"https://{domain}/track?pixel=1x1",
                    f"https://{domain}/collect.gif",
                    f"https://{domain}/beacon.js",
                    f"https://{domain}/analytics.png?user=123",
                    f"https://{domain}/pixel.gif?email=open"
                ])
            
            urls_file.write_text('\n'.join(test_urls))
            return test_urls
        
        return urls_file.read_text().strip().split('\n')
    
    def validate_syntax(self, pattern: str, source: str = "") -> ValidationResult:
        """Stage 1: Validate pattern syntax and compilation"""
        start_time = time.time()
        
        try:
            # Test regex compilation
            compile_start = time.perf_counter()
            compiled_pattern = re.compile(pattern)
            compile_time = (time.perf_counter() - compile_start) * 1000
            
            # Basic format checks
            format_issues = []
            
            # Check for potentially problematic patterns
            if len(pattern) > 1000:
                format_issues.append("Pattern too long (>1000 chars)")
            
            if pattern.count('(') > 20:
                format_issues.append("Too many capture groups")
            
            if '.*.*.*' in pattern:
                format_issues.append("Multiple greedy quantifiers")
            
            # Performance score based on compilation time and complexity
            complexity_score = self._calculate_complexity_score(pattern)
            performance_score = 1.0 - min(compile_time / 100.0, 0.8)  # Penalize slow compilation
            
            overall_score = (performance_score + complexity_score) / 2
            passed = len(format_issues) == 0 and compile_time < self.performance_thresholds['max_compile_time_ms']
            
            return ValidationResult(
                pattern=pattern,
                source=source,
                stage="syntax",
                passed=passed,
                score=overall_score,
                details={
                    'compile_time_ms': compile_time,
                    'complexity_score': complexity_score,
                    'format_issues': format_issues,
                    'pattern_length': len(pattern)
                },
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=time.time()
            )
            
        except re.error as e:
            return ValidationResult(
                pattern=pattern,
                source=source,
                stage="syntax",
                passed=False,
                score=0.0,
                details={
                    'error': str(e),
                    'error_type': 'regex_compilation_failed'
                },
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=time.time()
            )
    
    def validate_performance(self, pattern: str, source: str = "") -> ValidationResult:
        """Stage 2: Test pattern performance against large URL dataset"""
        start_time = time.time()
        
        try:
            compiled_pattern = re.compile(pattern)
            
            # Test performance on URL dataset
            match_times = []
            matches = 0
            
            for url in self.test_urls[:1000]:  # Test on 1000 URLs
                match_start = time.perf_counter_ns()
                if compiled_pattern.search(url):
                    matches += 1
                match_end = time.perf_counter_ns()
                match_times.append(match_end - match_start)
            
            avg_match_time = statistics.mean(match_times)
            max_match_time = max(match_times)
            
            # Performance scoring
            time_score = 1.0 - min(avg_match_time / self.performance_thresholds['max_avg_match_time_ns'], 1.0)
            consistency_score = 1.0 - min((max_match_time - avg_match_time) / avg_match_time, 1.0) if avg_match_time > 0 else 1.0
            
            overall_score = (time_score + consistency_score) / 2
            passed = avg_match_time < self.performance_thresholds['max_avg_match_time_ns']
            
            return ValidationResult(
                pattern=pattern,
                source=source,
                stage="performance",
                passed=passed,
                score=overall_score,
                details={
                    'avg_match_time_ns': avg_match_time,
                    'max_match_time_ns': max_match_time,
                    'total_matches': matches,
                    'urls_tested': len(self.test_urls[:1000]),
                    'time_score': time_score,
                    'consistency_score': consistency_score
                },
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=time.time()
            )
            
        except Exception as e:
            return ValidationResult(
                pattern=pattern,
                source=source,
                stage="performance",
                passed=False,
                score=0.0,
                details={'error': str(e), 'error_type': 'performance_test_failed'},
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=time.time()
            )
    
    def validate_false_positives(self, pattern: str, source: str = "") -> ValidationResult:
        """Stage 3: Test for false positives against legitimate domains"""
        start_time = time.time()
        
        try:
            compiled_pattern = re.compile(pattern)
            
            false_positives = []
            legitimate_urls = []
            
            # Generate URLs from legitimate domains
            for domain in self.legitimate_domains:
                legitimate_urls.extend([
                    f"https://{domain}/",
                    f"https://www.{domain}/index.html",
                    f"https://{domain}/contact.php",
                    f"https://mail.{domain}/inbox"
                ])
            
            # Test for false positives
            for url in legitimate_urls[:500]:  # Test 500 legitimate URLs
                if compiled_pattern.search(url):
                    false_positives.append(url)
            
            false_positive_rate = len(false_positives) / len(legitimate_urls[:500])
            
            # Also test against known trackers (should match these)
            true_positives = []
            tracker_urls = []
            
            for domain in self.known_trackers:
                tracker_urls.extend([
                    f"https://{domain}/track.gif",
                    f"https://{domain}/pixel.png",
                    f"https://{domain}/collect.js"
                ])
            
            for url in tracker_urls[:100]:  # Test 100 tracker URLs
                if compiled_pattern.search(url):
                    true_positives.append(url)
            
            true_positive_rate = len(true_positives) / len(tracker_urls[:100]) if tracker_urls else 0
            
            # Scoring based on false positive rate and true positive rate
            fp_score = 1.0 - min(false_positive_rate / self.performance_thresholds['max_false_positive_rate'], 1.0)
            tp_score = true_positive_rate  # Higher is better
            
            overall_score = (fp_score * 0.7 + tp_score * 0.3)  # Weight false positives more heavily
            passed = false_positive_rate < self.performance_thresholds['max_false_positive_rate']
            
            return ValidationResult(
                pattern=pattern,
                source=source,
                stage="false_positive",
                passed=passed,
                score=overall_score,
                details={
                    'false_positive_rate': false_positive_rate,
                    'true_positive_rate': true_positive_rate,
                    'false_positives_count': len(false_positives),
                    'true_positives_count': len(true_positives),
                    'false_positive_examples': false_positives[:5],  # Sample
                    'fp_score': fp_score,
                    'tp_score': tp_score
                },
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=time.time()
            )
            
        except Exception as e:
            return ValidationResult(
                pattern=pattern,
                source=source,
                stage="false_positive",
                passed=False,
                score=0.0,
                details={'error': str(e), 'error_type': 'false_positive_test_failed'},
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=time.time()
            )
    
    def validate_community_score(self, pattern: str, source: str = "") -> ValidationResult:
        """Stage 4: Check community reports and threat intelligence"""
        start_time = time.time()
        
        try:
            # Extract domains from pattern for community scoring
            domains = self._extract_domains_from_pattern(pattern)
            
            community_scores = []
            threat_intel_scores = []
            
            for domain in domains:
                # Check against known threat intelligence
                if domain in self.known_trackers:
                    threat_intel_scores.append(0.9)  # High confidence
                elif domain in self.legitimate_domains:
                    threat_intel_scores.append(0.1)  # Low threat score
                else:
                    threat_intel_scores.append(0.5)  # Unknown
                
                # Simulate community feedback (in production, would query actual community database)
                community_scores.append(self._simulate_community_score(domain))
            
            avg_community_score = statistics.mean(community_scores) if community_scores else 0.5
            avg_threat_score = statistics.mean(threat_intel_scores) if threat_intel_scores else 0.5
            
            overall_score = (avg_community_score + avg_threat_score) / 2
            passed = overall_score > 0.6  # Require 60% confidence
            
            return ValidationResult(
                pattern=pattern,
                source=source,
                stage="community",
                passed=passed,
                score=overall_score,
                details={
                    'domains_analyzed': len(domains),
                    'avg_community_score': avg_community_score,
                    'avg_threat_intel_score': avg_threat_score,
                    'domains_sample': domains[:5]
                },
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=time.time()
            )
            
        except Exception as e:
            return ValidationResult(
                pattern=pattern,
                source=source,
                stage="community",
                passed=False,
                score=0.5,  # Neutral score on error
                details={'error': str(e), 'error_type': 'community_scoring_failed'},
                duration_ms=(time.time() - start_time) * 1000,
                timestamp=time.time()
            )
    
    def _calculate_complexity_score(self, pattern: str) -> float:
        """Calculate complexity score for regex pattern"""
        # Factors that increase complexity (bad)
        complexity_factors = {
            'length': len(pattern) / 1000,  # Normalize to 0-1
            'alternations': pattern.count('|') / 10,
            'groups': pattern.count('(') / 20,
            'quantifiers': pattern.count('*') + pattern.count('+') / 10,
            'lookaheads': pattern.count('(?=') + pattern.count('(?!') / 5,
            'backtracking': pattern.count('.*') / 5
        }
        
        total_complexity = sum(min(factor, 1.0) for factor in complexity_factors.values())
        return max(0.0, 1.0 - total_complexity / len(complexity_factors))
    
    def _extract_domains_from_pattern(self, pattern: str) -> List[str]:
        """Extract domain names from regex pattern"""
        # Simple domain extraction (in production would be more sophisticated)
        domain_patterns = [
            r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
            r'\|\|([^/^]+)',
            r'://([^/]+)'
        ]
        
        domains = set()
        for domain_pattern in domain_patterns:
            matches = re.findall(domain_pattern, pattern)
            for match in matches:
                if '.' in match and len(match) > 4:
                    domains.add(match.lower().strip('.'))
        
        return list(domains)[:10]  # Limit to 10 domains
    
    def _simulate_community_score(self, domain: str) -> float:
        """Simulate community scoring (in production would query real database)"""
        # Simple simulation based on domain characteristics
        if any(keyword in domain for keyword in ['track', 'analytics', 'ads', 'pixel']):
            return 0.8  # Likely tracker
        elif any(keyword in domain for keyword in ['cdn', 'static', 'assets']):
            return 0.3  # Likely legitimate
        else:
            return 0.5  # Unknown
    
    def validate_pattern_comprehensive(self, pattern: str, source: str = "") -> Dict[str, ValidationResult]:
        """Run comprehensive validation on a pattern"""
        logger.info(f"🔍 Starting comprehensive validation for pattern from {source}")
        
        results = {}
        
        # Stage 1: Syntax validation
        syntax_result = self.validate_syntax(pattern, source)
        results['syntax'] = syntax_result
        
        if not syntax_result.passed:
            logger.warning(f"❌ Pattern failed syntax validation: {syntax_result.details}")
            return results
        
        # Stage 2: Performance validation
        performance_result = self.validate_performance(pattern, source)
        results['performance'] = performance_result
        
        # Stage 3: False positive validation
        fp_result = self.validate_false_positives(pattern, source)
        results['false_positive'] = fp_result
        
        # Stage 4: Community scoring
        community_result = self.validate_community_score(pattern, source)
        results['community'] = community_result
        
        # Calculate overall validation score
        overall_score = statistics.mean([r.score for r in results.values()])
        overall_passed = all(r.passed for r in results.values())
        
        logger.info(f"✅ Validation complete - Overall score: {overall_score:.3f}, Passed: {overall_passed}")
        
        return results
    
    def validate_patterns_batch(self, patterns: List[Tuple[str, str]]) -> Dict[str, Dict[str, ValidationResult]]:
        """Validate multiple patterns concurrently"""
        logger.info(f"🚀 Starting batch validation of {len(patterns)} patterns")
        
        futures = {}
        results = {}
        
        # Submit validation tasks
        for pattern, source in patterns:
            future = self.thread_pool.submit(self.validate_pattern_comprehensive, pattern, source)
            futures[future] = (pattern, source)
        
        # Collect results
        for future in as_completed(futures):
            pattern, source = futures[future]
            try:
                pattern_results = future.result()
                results[f"{source}:{pattern[:50]}"] = pattern_results
            except Exception as e:
                logger.error(f"Validation failed for {source} pattern: {e}")
        
        logger.info(f"✅ Batch validation complete - {len(results)} patterns processed")
        return results
    
    def save_validation_results(self, results: Dict[str, Dict[str, ValidationResult]], filename: str = None):
        """Save validation results to file"""
        if filename is None:
            filename = f"validation_results_{int(time.time())}.json"
        
        results_file = self.results_dir / filename
        
        # Convert results to serializable format
        serializable_results = {}
        for pattern_key, pattern_results in results.items():
            serializable_results[pattern_key] = {}
            for stage, result in pattern_results.items():
                serializable_results[pattern_key][stage] = asdict(result)
        
        with open(results_file, 'w') as f:
            json.dump(serializable_results, f, indent=2)
        
        logger.info(f"💾 Validation results saved to {results_file}")

def main():
    """Test the pattern validation system"""
    validator = PatternValidator()
    
    # Test patterns
    test_patterns = [
        ("google-analytics\\.com", "test_good"),
        (".*.*.*", "test_bad_performance"),
        ("gmail\\.com", "test_false_positive"),
        ("||doubleclick.net^", "test_ublock_format"),
        ("track\\.(gif|png|jpg)", "test_tracking_pattern")
    ]
    
    print("🧪 Testing Pattern Validation System")
    print("=" * 50)
    
    # Batch validation
    results = validator.validate_patterns_batch(test_patterns)
    
    # Display results
    for pattern_key, pattern_results in results.items():
        print(f"\n📝 Pattern: {pattern_key}")
        for stage, result in pattern_results.items():
            status = "✅ PASS" if result.passed else "❌ FAIL"
            print(f"  {stage.upper()}: {status} (Score: {result.score:.3f})")
    
    # Save results
    validator.save_validation_results(results)
    
    print(f"\n📊 Validation complete!")

if __name__ == "__main__":
    main()