"""
Cache manager pentru threat intelligence - evită reîncărcarea constantă
"""

import json
import pickle
import re
import time
from pathlib import Path
from datetime import datetime, timedelta

class ThreatIntelligenceCache:
    """Gestionează cache-ul pentru threat intelligence."""
    
    def __init__(self, cache_dir="../cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_duration = timedelta(hours=6)  # Cache pentru 6 ore
    
    def _get_cache_path(self, source_name):
        """Returnează calea către fișierul de cache."""
        return self.cache_dir / f"{source_name}_cache.json"
    
    def is_cache_valid(self, source_name):
        """Verifică dacă cache-ul este încă valid."""
        cache_path = self._get_cache_path(source_name)
        
        if not cache_path.exists():
            return False
        
        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
            
            cache_time = datetime.fromisoformat(cache_data.get('timestamp', '1970-01-01'))
            return datetime.now() - cache_time < self.cache_duration
            
        except Exception:
            return False
    
    def load_from_cache(self, source_name):
        """Încarcă datele din cache."""
        cache_path = self._get_cache_path(source_name)
        
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            print(f"    [✓] Loaded {source_name} from cache ({cache_data['count']} items)")
            return cache_data.get('data', [])
            
        except Exception as e:
            print(f"    [-] Cache load error for {source_name}: {e}")
            return []
    
    def save_to_cache(self, source_name, data):
        """Salvează datele în cache."""
        cache_path = self._get_cache_path(source_name)
        
        try:
            cache_data = {
                'timestamp': datetime.now().isoformat(),
                'count': len(data) if isinstance(data, (list, set)) else 1,
                'data': data if isinstance(data, (list, dict)) else list(data)
            }
            
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_data, f, indent=2, ensure_ascii=False)
            
            print(f"    [✓] Cached {source_name} ({cache_data['count']} items)")
            
        except Exception as e:
            print(f"    [-] Cache save error for {source_name}: {e}")
    
    def clear_cache(self):
        """Șterge toate fișierele de cache."""
        for cache_file in self.cache_dir.glob("*_cache.json"):
            cache_file.unlink()
        print("[+] Cache cleared")

class OptimizedThreatIntelligence:
    """Versiune optimizată cu cache pentru threat intelligence."""
    
    def __init__(self):
        self.cache = ThreatIntelligenceCache()
        self.phishing_domains = set()
        self.malware_domains = set()
        self.tracking_patterns = []
        self.suspicious_services = {}
    
    def load_optimized_sources(self, force_refresh=False):
        """Încarcă sursele cu optimizare cache."""
        print("[+] Încărcare optimizată threat intelligence...")
        
        # 1. MailTrackerBlocker
        if force_refresh or not self.cache.is_cache_valid("mailtracker"):
            print("    [+] Procesez MailTrackerBlocker...")
            patterns = self._load_mailtracker_fresh()
            self.cache.save_to_cache("mailtracker", patterns)
        else:
            patterns = self.cache.load_from_cache("mailtracker")
        
        self.tracking_patterns.extend(patterns)
        
        # 2. EasyPrivacy
        if force_refresh or not self.cache.is_cache_valid("easyprivacy"):
            print("    [+] Procesez EasyPrivacy...")
            domains = self._load_easyprivacy_fresh()
            self.cache.save_to_cache("easyprivacy", list(domains))
        else:
            domains = set(self.cache.load_from_cache("easyprivacy"))
        
        self.phishing_domains.update(domains)
        
        # 3. UglyEmail
        if force_refresh or not self.cache.is_cache_valid("uglyemail"):
            print("    [+] Procesez UglyEmail...")
            services = self._load_uglyemail_fresh()
            self.cache.save_to_cache("uglyemail", services)
        else:
            services = self.cache.load_from_cache("uglyemail")
        
        for service in services:
            self.suspicious_services[service['domain']] = service
        
        # 4. PhishTank (doar dacă forțăm sau cache-ul e expirat)
        if force_refresh or not self.cache.is_cache_valid("phishtank"):
            print("    [+] Descărcare PhishTank...")
            try:
                phish_domains = self._load_phishtank_fresh()
                self.cache.save_to_cache("phishtank", list(phish_domains))
                self.phishing_domains.update(phish_domains)
            except Exception as e:
                print(f"    [-] Eroare PhishTank: {e}")
                # Încearcă să încarce din cache chiar dacă e expirat
                cached_domains = self.cache.load_from_cache("phishtank")
                if cached_domains:
                    self.phishing_domains.update(cached_domains)
        else:
            cached_domains = self.cache.load_from_cache("phishtank")
            self.phishing_domains.update(cached_domains)
    
    def _load_mailtracker_fresh(self):
        """Încarcă MailTrackerBlocker fresh cu pattern-uri detaliate."""
        patterns = []
        try:
            with open("sources/mailtrackerblocker.json", 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            for entry in data:
                if isinstance(entry, dict) and "include" in entry:
                    for pattern in entry["include"]:
                        # Extrage domeniul din pattern cu logică îmbunătățită
                        domain = self._extract_domain_from_pattern(pattern)
                        if domain:
                            patterns.append({
                                "pattern": pattern,
                                "domain": domain,
                                "regex_pattern": pattern,  # Pentru matching avansat
                                "source": "MailTrackerBlocker",
                                "confidence": "high"
                            })
        except Exception as e:
            print(f"    [-] Eroare MailTrackerBlocker: {e}")
        
        return patterns
    
    def _extract_domain_from_pattern(self, pattern):
        """Extrage domeniul dintr-un pattern MailTrackerBlocker cu regex avansat."""
        import re
        
        # Elimină prefixele și wildcards
        clean_pattern = pattern.replace("*://", "").replace("/*", "").replace("*", "")
        
        # Găsește primul segment care arată ca un domeniu valid
        domain_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', clean_pattern)
        if domain_match:
            domain = domain_match.group(1)
            # Elimină subdomeniile "*" dacă există
            if domain.startswith('.'):
                domain = domain[1:]
            return domain
        
        # Fallback la metoda veche
        if "/" in clean_pattern:
            domain = clean_pattern.split("/")[0]
        else:
            domain = clean_pattern
            
        return domain if domain and "." in domain else None
    
    def _load_easyprivacy_fresh(self):
        """Încarcă EasyPrivacy fresh - extrage DOAR din surse open source, fără hardcoding."""
        domains = set()
        try:
            with open("sources/easyprivacy.txt", 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("!") or line.startswith("["):
                        continue
                    
                    # ELIMINAT: Lista hardcodată de tracking_indicators
                    # Acum procesăm TOATE liniile din EasyPrivacy fără filtrare hardcodată
                    
                    # Extragere domeniu direct din formatul EasyPrivacy
                    clean_line = line.replace("||", "").replace("^", "").replace("*", "")
                    
                    # Diferite formate EasyPrivacy
                    if "/" in clean_line:
                        domain = clean_line.split("/")[0]
                    else:
                        domain = clean_line
                    
                    # Verificare validitate domeniu îmbunătățită
                    if (domain and "." in domain and len(domain) > 3 and 
                        not domain.startswith(".") and self._is_valid_tracking_domain(domain)):
                        domains.add(domain)
                    
                    # Căutare suplimentară pentru domenii în reguli complexe
                    if "||" in line or "//" in line:
                        import re
                        # Extrage toate domeniile din linie
                        domain_matches = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', line)
                        for found_domain in domain_matches:
                            if self._is_valid_tracking_domain(found_domain):
                                domains.add(found_domain)
                                
        except Exception as e:
            print(f"    [-] Eroare EasyPrivacy: {e}")
        
        return domains
    
    def _is_valid_tracking_domain(self, domain):
        """Verifică dacă domeniul e valid - fără filtrare hardcodată pe TLD-uri."""
        # Exclude doar domenii evidente invalid (foarte minim)
        obvious_invalid = ['localhost', '127.0.0.1', '0.0.0.0']
        if domain.lower() in obvious_invalid:
            return False
        
        # Verificare format domeniu basic
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        # TLD minim valid (orice TLD de cel puțin 2 caractere)
        tld = parts[-1].lower()
        
        return (len(domain) >= 4 and 
                len(tld) >= 2 and 
                not domain.startswith('-') and 
                not domain.endswith('-'))
    
    def _load_uglyemail_fresh(self):
        """Încarcă UglyEmail fresh."""
        services = []
        try:
            with open("sources/uglyemail.txt", 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if '@@=' in line:
                        service, pattern = line.split('@@=', 1)
                        domains = re.findall(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', pattern)
                        
                        for domain in domains:
                            services.append({
                                "domain": domain,
                                "service": service,
                                "pattern": pattern,
                                "source": "UglyEmail",
                                "confidence": "high"
                            })
        except Exception as e:
            print(f"    [-] Eroare UglyEmail: {e}")
        
        return services
    
    def _load_phishtank_fresh(self):
        """Încarcă PhishTank fresh."""
        import requests
        from urllib.parse import urlparse
        
        domains = set()
        url = "http://data.phishtank.com/data/online-valid.json"
        
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            phish_data = response.json()
            
            for entry in phish_data[:100]:  # Limitez pentru performanță
                phish_url = entry.get("url", "")
                if phish_url:
                    domain = urlparse(phish_url).netloc
                    if domain:
                        domains.add(domain)
        
        return domains
    
    def get_statistics(self):
        """Returnează statistici despre threat intelligence."""
        return {
            "phishing_domains": len(self.phishing_domains),
            "malware_domains": len(self.malware_domains),
            "tracking_patterns": len(self.tracking_patterns),
            "suspicious_services": len(self.suspicious_services),
            "total_threats": len(self.phishing_domains) + len(self.malware_domains)
        }

def main():
    """Testează sistemul optimizat."""
    print("[+] Testez sistemul optimizat de threat intelligence...")
    
    # Prima rulare (va încărca fresh)
    print("\n=== PRIMA RULARE (FRESH) ===")
    threat_intel = OptimizedThreatIntelligence()
    start_time = time.time()
    threat_intel.load_optimized_sources(force_refresh=True)
    fresh_time = time.time() - start_time
    
    stats1 = threat_intel.get_statistics()
    print(f"[+] Prima rulare: {fresh_time:.2f}s")
    print(f"    Domenii phishing: {stats1['phishing_domains']}")
    print(f"    Pattern-uri tracking: {stats1['tracking_patterns']}")
    
    # A doua rulare (va folosі cache)
    print("\n=== A DOUA RULARE (CACHE) ===")
    threat_intel2 = OptimizedThreatIntelligence()
    start_time = time.time()
    threat_intel2.load_optimized_sources(force_refresh=False)
    cache_time = time.time() - start_time
    
    stats2 = threat_intel2.get_statistics()
    print(f"[+] A doua rulare: {cache_time:.2f}s")
    print(f"    Domenii phishing: {stats2['phishing_domains']}")
    print(f"    Pattern-uri tracking: {stats2['tracking_patterns']}")
    
    improvement = ((fresh_time - cache_time) / fresh_time) * 100
    print(f"\n[+] 🚀 Îmbunătățire performanță: {improvement:.1f}% mai rapid cu cache!")

if __name__ == "__main__":
    main()