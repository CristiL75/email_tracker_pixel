#!/usr/bin/env python3
"""
Optimized Pattern Matching Engine

High-performance tracking detection with:
- O(1) domain lookups using hash maps
- Intelligent pattern caching
- Parallel processing for batch analysis
- Memory-efficient indexing

Replaces O(n) regex scanning with optimized data structures.
"""

import json
import re
import time
import threading
from pathlib import Path
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib

class OptimizedPatternEngine:
    """High-performance pattern matching engine with O(1) domain lookups."""
    
    def __init__(self):
        self.base_path = Path(__file__).parent.parent
        
        # High-performance indexes
        self.domain_index = {}  # domain -> threat_info
        self.url_pattern_index = defaultdict(list)  # domain -> [url_patterns]
        self.regex_pattern_cache = {}  # pattern_hash -> compiled_regex
        
        # Statistics
        self.stats = {
            'domains_indexed': 0,
            'patterns_cached': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'total_lookups': 0
        }
        
        # Threading
        self.max_workers = 4
        self._lock = threading.Lock()
        
        # Load and index patterns
        self._initialize_indexes()
    
    def _initialize_indexes(self):
        """Initialize high-performance pattern indexes."""
        print("[+] 🚀 Inițializez motor optimizat de pattern-uri...")
        start_time = time.time()
        
        # 1. Index MailTracker patterns
        self._index_mailtracker_patterns()
        
        # 2. Index GitHub patterns  
        self._index_github_patterns()
        
        # 3. Pre-compile frequently used regex patterns
        self._precompile_common_patterns()
        
        load_time = time.time() - start_time
        print(f"[+] ✅ Motor optimizat inițializat în {load_time:.3f}s")
        print(f"[+] 📊 Performanță:")
        print(f"    🗂️  Domenii indexate: {self.stats['domains_indexed']:,}")
        print(f"    🎯 Pattern-uri cached: {self.stats['patterns_cached']:,}")
        print(f"    ⚡ Timp inițializare: {load_time:.3f}s")
    
    def _index_mailtracker_patterns(self):
        """Index MailTracker patterns for O(1) domain lookups."""
        cache_file = self.base_path / "cache" / "mailtracker_cache.json"
        if not cache_file.exists():
            return
        
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            for item in cache_data.get('data', []):
                pattern = item.get('pattern', '')
                domain = item.get('domain', '')
                
                if domain and pattern:
                    # Extract base domain for indexing
                    base_domain = self._extract_base_domain(domain)
                    
                    if base_domain not in self.domain_index:
                        self.domain_index[base_domain] = {
                            'threat_level': 'critical',
                            'source': 'MailTracker',
                            'patterns': [],
                            'confidence': 'high'
                        }
                    
                    self.domain_index[base_domain]['patterns'].append({
                        'pattern': pattern,
                        'regex_pattern': item.get('regex_pattern', ''),
                        'confidence': item.get('confidence', 'high')
                    })
                    
                    self.stats['domains_indexed'] += 1
            
            print(f"    [✓] MailTracker: {len([d for d in self.domain_index if self.domain_index[d]['source'] == 'MailTracker'])} domenii indexate")
            
        except Exception as e:
            print(f"    [-] Eroare indexare MailTracker: {e}")
    
    def _index_github_patterns(self):
        """Index GitHub patterns for fast domain-based lookups."""
        github_file = self.base_path / "sources" / "github_tracking_rules.json"
        if not github_file.exists():
            return
        
        try:
            with open(github_file, 'r', encoding='utf-8') as f:
                github_data = json.load(f)
            
            # Index domains from GitHub
            github_domains = 0
            for domain in github_data.get('domains', []):
                if len(domain) > 3 and '.' in domain:
                    base_domain = self._extract_base_domain(domain)
                    
                    if base_domain not in self.domain_index:
                        self.domain_index[base_domain] = {
                            'threat_level': 'medium',
                            'source': 'GitHub',
                            'patterns': [],
                            'confidence': 'medium'
                        }
                        github_domains += 1
                    
                    # Add URL patterns for this domain
                    for url_pattern in github_data.get('url_patterns', []):
                        if len(url_pattern) > 5:
                            self.url_pattern_index[base_domain].append(url_pattern)
            
            print(f"    [✓] GitHub: {github_domains} domenii noi indexate")
            
        except Exception as e:
            print(f"    [-] Eroare indexare GitHub: {e}")
    
    def _extract_base_domain(self, domain: str) -> str:
        """Extract base domain for indexing (www.example.com -> example.com)."""
        domain = domain.lower().strip()
        
        # Remove www prefix
        if domain.startswith('www.'):
            domain = domain[4:]
        
        # Remove protocol if present
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        
        # Remove path if present
        if '/' in domain:
            domain = domain.split('/', 1)[0]
        
        return domain
    
    def _precompile_common_patterns(self):
        """Pre-compile frequently used regex patterns for performance."""
        common_patterns = [
            r'(?:src|href)=[\"\']([^\"\']*track[^\"\']*)',
            r'(?:src|href)=[\"\']([^\"\']*pixel[^\"\']*)',
            r'(?:src|href)=[\"\']([^\"\']*analytics[^\"\']*)',
            r'(?:src|href)=[\"\']([^\"\']*beacon[^\"\']*)',
            r'(?:src|href)=[\"\']([^\"\']*collect[^\"\']*)',
            r'<img[^>]*src=[\"\']([^\"\']+)[\"\'][^>]*>',
            r'width=["\']?1["\']?[^>]*height=["\']?1["\']?',
            r'height=["\']?1["\']?[^>]*width=["\']?1["\']?',
            r'style=["\'][^"\']*display:\s*none[^"\']*["\']',
            r'style=["\'][^"\']*width:\s*1px[^"\']*["\']'
        ]
        
        for pattern in common_patterns:
            pattern_hash = hashlib.md5(pattern.encode()).hexdigest()
            try:
                self.regex_pattern_cache[pattern_hash] = re.compile(pattern, re.IGNORECASE)
                self.stats['patterns_cached'] += 1
            except re.error:
                continue
        
        print(f"    [✓] Pre-compiled: {len(self.regex_pattern_cache)} regex patterns")
    
    def fast_domain_lookup(self, url: str) -> Optional[Dict]:
        """O(1) domain threat lookup."""
        self.stats['total_lookups'] += 1
        
        # Extract domain from URL
        domain = self._extract_domain_from_url(url)
        if not domain:
            return None
        
        base_domain = self._extract_base_domain(domain)
        
        # O(1) hash table lookup
        if base_domain in self.domain_index:
            self.stats['cache_hits'] += 1
            return self.domain_index[base_domain]
        
        self.stats['cache_misses'] += 1
        return None
    
    def _extract_domain_from_url(self, url: str) -> str:
        """Extract domain from URL."""
        try:
            if '://' in url:
                url = url.split('://', 1)[1]
            
            if '/' in url:
                url = url.split('/', 1)[0]
            
            return url.lower()
        except:
            return ""
    
    def batch_analyze_urls(self, urls: List[str]) -> List[Dict]:
        """Parallel analysis of multiple URLs."""
        if not urls:
            return []
        
        results = []
        
        # Use thread pool for parallel processing
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all URL analysis tasks
            future_to_url = {
                executor.submit(self._analyze_single_url, url): url 
                for url in urls
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    print(f"    [-] Eroare analiza URL {url}: {e}")
        
        return results
    
    def _analyze_single_url(self, url: str) -> Optional[Dict]:
        """Analyze single URL for tracking patterns."""
        # Fast domain lookup first
        threat_info = self.fast_domain_lookup(url)
        if not threat_info:
            return None
        
        # Extract URL components
        domain = self._extract_domain_from_url(url)
        
        # Build result
        result = {
            'url': url,
            'domain': domain,
            'threat_level': threat_info['threat_level'],
            'source': threat_info['source'],
            'confidence': threat_info['confidence'],
            'patterns_matched': len(threat_info['patterns']),
            'is_malicious': threat_info['threat_level'] in ['critical', 'high']
        }
        
        # Check URL patterns for this domain
        base_domain = self._extract_base_domain(domain)
        if base_domain in self.url_pattern_index:
            for pattern in self.url_pattern_index[base_domain]:
                if pattern.lower() in url.lower():
                    result['url_pattern_match'] = pattern
                    break
        
        return result
    
    def extract_urls_from_content(self, content: str) -> List[str]:
        """Fast URL extraction using pre-compiled patterns."""
        urls = set()
        
        # Use cached compiled patterns
        img_pattern_hash = hashlib.md5(r'<img[^>]*src=[\"\']([^\"\']+)[\"\'][^>]*>'.encode()).hexdigest()
        
        if img_pattern_hash in self.regex_pattern_cache:
            pattern = self.regex_pattern_cache[img_pattern_hash]
            matches = pattern.findall(content)
            urls.update(matches)
        
        # Additional fast extraction patterns
        for pattern_key in ['href', 'background', 'url']:
            pattern_hash = hashlib.md5(f'(?:src|href)=[\"\']([^\"\']*{pattern_key}[^\"\']*'.encode()).hexdigest()
            if pattern_hash in self.regex_pattern_cache:
                pattern = self.regex_pattern_cache[pattern_hash]
                matches = pattern.findall(content)
                urls.update(matches)
        
        return list(urls)
    
    def analyze_email_content(self, email_content: str) -> Dict:
        """High-performance email content analysis."""
        start_time = time.time()
        
        # Fast URL extraction
        urls = self.extract_urls_from_content(email_content)
        
        # Parallel URL analysis
        threat_results = self.batch_analyze_urls(urls)
        
        # Calculate metrics
        total_threats = len(threat_results)
        critical_threats = len([r for r in threat_results if r['threat_level'] == 'critical'])
        high_threats = len([r for r in threat_results if r['threat_level'] == 'high'])
        
        analysis_time = time.time() - start_time
        
        return {
            'analysis_time': analysis_time,
            'urls_extracted': len(urls),
            'threats_detected': total_threats,
            'critical_threats': critical_threats,
            'high_threats': high_threats,
            'threat_details': threat_results,
            'performance_stats': {
                'cache_hit_rate': self.stats['cache_hits'] / max(self.stats['total_lookups'], 1) * 100,
                'total_lookups': self.stats['total_lookups'],
                'analysis_speed': len(urls) / max(analysis_time, 0.001)  # URLs per second
            }
        }
    
    def get_performance_stats(self) -> Dict:
        """Get detailed performance statistics."""
        total_lookups = max(self.stats['total_lookups'], 1)
        
        return {
            'domains_indexed': self.stats['domains_indexed'],
            'patterns_cached': self.stats['patterns_cached'],
            'cache_hit_rate': (self.stats['cache_hits'] / total_lookups) * 100,
            'cache_efficiency': {
                'hits': self.stats['cache_hits'],
                'misses': self.stats['cache_misses'],
                'total_lookups': self.stats['total_lookups']
            },
            'memory_usage': {
                'domain_index_size': len(self.domain_index),
                'url_pattern_index_size': len(self.url_pattern_index),
                'regex_cache_size': len(self.regex_pattern_cache)
            }
        }


def main():
    """Test the optimized pattern engine."""
    print("🚀 Testing Optimized Pattern Engine")
    print("=" * 50)
    
    # Initialize engine
    engine = OptimizedPatternEngine()
    
    # Test URLs
    test_urls = [
        "https://track.flexlinks.com/a.ashx?tc=123456&id=user123",
        "https://cc.zdnet.com/v1/otc/pixel.gif?campaign=newsletter",
        "https://www.pntrac.com/t/track?id=campaign123",
        "https://google.com/search?q=test",
        "https://facebook.com/pixel.gif"
    ]
    
    print(f"\n📊 Testing {len(test_urls)} URLs...")
    
    # Test individual lookups
    for url in test_urls:
        result = engine.fast_domain_lookup(url)
        status = "🔴 THREAT" if result else "✅ Clean"
        print(f"  {status} {url}")
    
    # Test batch analysis
    print(f"\n⚡ Batch analysis...")
    batch_results = engine.batch_analyze_urls(test_urls)
    print(f"  Threats detected: {len(batch_results)}")
    
    # Performance stats
    stats = engine.get_performance_stats()
    print(f"\n📈 Performance Stats:")
    print(f"  Cache hit rate: {stats['cache_hit_rate']:.1f}%")
    print(f"  Domains indexed: {stats['domains_indexed']:,}")
    print(f"  Patterns cached: {stats['patterns_cached']:,}")


if __name__ == "__main__":
    main()