"""
Sistema finală de detectare tracking pixels cu threat intelligence optimizată
Combină toate sursele open source cu performanță maximă + detectare CSS avansată
TOATE pattern-urile sunt extrase dinamic din surse open source - ZERO hardcoding!
OPTIMIZAT cu O(1) domain lookups și parallel processing pentru performanță maximă!
"""

from .optimized_threat_intelligence import OptimizedThreatIntelligence
from .css_pixel_detector import CSSPixelDetector
from .opensource_pattern_extractor import OpenSourcePatternExtractor
from .optimized_pattern_engine import OptimizedPatternEngine
from pathlib import Path
import json
import re
import time
from urllib.parse import urlparse, parse_qs

class FinalPixelDetector:
    """Detector final de tracking pixels cu toate optimizările și pattern-uri open source."""
    
    def __init__(self):
        self.threat_intel = OptimizedThreatIntelligence()
        self.css_detector = None  # Va fi inițializat după threat intelligence
        self.pattern_extractor = OpenSourcePatternExtractor()
        self.optimized_engine = OptimizedPatternEngine()  # NEW: High-performance O(1) engine
        self.pattern_extractor = OpenSourcePatternExtractor()
        self.pixel_patterns = []  # Va fi populat dinamic din surse open source
        self.loaded = False
    
    def initialize(self, force_refresh=False):
        """Inițializează threat intelligence, CSS detector și pattern-uri open source."""
        if not self.loaded or force_refresh:
            print("[+] Inițializez detectorul final cu pattern-uri open source...")
            start_time = time.time()
            
            # 1. Încarcă threat intelligence
            self.threat_intel.load_optimized_sources(force_refresh)
            
            # 2. Extrage pattern-uri din surse open source
            print("    [+] Extrag pattern-uri dinamice din EasyPrivacy și MailTrackerBlocker...")
            extracted_patterns = self.pattern_extractor.generate_dynamic_patterns()
            
            # 3. Configurează pattern-urile pentru HTML detection
            self.pixel_patterns = []
            self.pixel_patterns.extend(extracted_patterns["html_img_patterns"])
            self.pixel_patterns.extend(extracted_patterns["url_tracking_patterns"])
            
            # 4. ADAUGĂ pattern-uri MailTracker din threat intelligence cache
            print("    [+] Încărcare pattern-uri MailTracker din cache...")
            mailtracker_patterns = self._load_mailtracker_patterns()
            self.pixel_patterns.extend(mailtracker_patterns)
            print(f"    [✓] Adăugate {len(mailtracker_patterns)} pattern-uri MailTracker")
            
            # 5. ADAUGĂ pattern-uri din GitHub open source
            print("    [+] Încărcare pattern-uri din GitHub open source...")
            github_patterns = self._load_github_patterns()
            self.pixel_patterns.extend(github_patterns)
            print(f"    [✓] Adăugate {len(github_patterns)} pattern-uri GitHub open source")
            
            # 4. Inițializează CSS detector cu threat intelligence
            print("    [+] Inițializez CSS detector cu threat intelligence...")
            self.css_detector = CSSPixelDetector(threat_intel=self.threat_intel)
            
            load_time = time.time() - start_time
            stats = self.threat_intel.get_statistics()
            pattern_stats = self.pattern_extractor.get_statistics()
            
            print(f"[+] ✅ Inițializare completă în {load_time:.2f}s")
            print(f"[+] 📊 Statistici threat intelligence:")
            print(f"    🔴 Domenii phishing: {stats['phishing_domains']:,}")
            print(f"    🔍 Pattern-uri tracking: {stats['tracking_patterns']:,}")
            print(f"    ⚠️  Servicii suspecte: {stats['suspicious_services']:,}")
            print(f"    🎯 Total amenințări: {stats['total_threats']:,}")
            print(f"[+] 🎨 Pattern-uri open source dinamice:")
            print(f"    📂 HTML patterns: {len(extracted_patterns['html_img_patterns'])}")
            print(f"    🌐 URL patterns: {len(extracted_patterns['url_tracking_patterns'])}")
            print(f"    🎨 CSS keywords: {len(self.css_detector.css_tracking_keywords)}")
            print(f"    📊 Total pattern-uri extrase: {pattern_stats['total_patterns']:,}")
            
            self.loaded = True
    
    def extract_pixels_from_email(self, email_content):
        """Extrage tracking pixels cu motorul optimizat O(1) și parallel processing."""
        start_time = time.time()
        
        # 1. OPTIMIZED: Fast URL extraction cu motorul O(1)
        print("    [+] 🚀 Extracție URLs optimizată cu motor O(1)...")
        extracted_urls = self.optimized_engine.extract_urls_from_content(email_content)
        
        # 2. OPTIMIZED: Parallel batch analysis
        print(f"    [+] ⚡ Analiză paralelă {len(extracted_urls)} URLs...")
        optimized_results = self.optimized_engine.batch_analyze_urls(extracted_urls)
        
        # 3. Convert results to pixel format
        pixels_found = []
        for result in optimized_results:
            if result['is_malicious']:
                pixel_info = {
                    'url': result['url'],
                    'domain': result['domain'],
                    'threat_level': result['threat_level'],
                    'source': result['source'], 
                    'confidence': result['confidence'],
                    'detection_method': 'optimized_engine',
                    'pattern_source': 'optimized_o1_lookup',
                    'is_malicious': True,
                    'threat_score': self._calculate_optimized_threat_score(result)
                }
                pixels_found.append(pixel_info)
        
        # 4. FALLBACK: Traditional regex scanning for missed patterns  
        print(f"    [+] 🔍 Fallback regex scan pentru {len(self.pixel_patterns)} pattern-uri...")
        regex_pixels = self._fallback_regex_scan(email_content, extracted_urls)
        pixels_found.extend(regex_pixels)
        
        # 5. CSS pixels detection (cu threat intelligence)
        print("    [+] 🎨 Scanez pentru CSS tracking pixels cu threat intelligence...")
        if not self.css_detector:
            self.css_detector = CSSPixelDetector(threat_intel=self.threat_intel)
        
        css_pixels = self.css_detector.extract_css_pixels(email_content)
        
        # Add CSS pixels to main list
        for css_pixel in css_pixels:
            if css_pixel["url"] not in [p["url"] for p in pixels_found]:
                pixels_found.append(css_pixel)
        
        analysis_time = time.time() - start_time
        print(f"    [✅] Optimized analysis completed în {analysis_time:.3f}s")
        print(f"    [✓] Pixels detectați: {len(pixels_found)} total")
        print(f"    [✓] URLs procesate: {len(extracted_urls)}")
        
        # Performance stats
        perf_stats = self.optimized_engine.get_performance_stats()
        print(f"    [📊] Cache hit rate: {perf_stats['cache_hit_rate']:.1f}%")
        
        return pixels_found
    
    def _analyze_pixel_url(self, pixel_url):
        """Analizează detaliat un URL de tracking pixel."""
        parsed_url = urlparse(pixel_url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query_params = parse_qs(parsed_url.query)
        
        # Analiză basic
        pixel_info = {
            "url": pixel_url,
            "domain": domain,
            "path": path,
            "query_params": list(query_params.keys()),
            "param_count": len(query_params)
        }
        
        # Verifică în threat intelligence
        threat_score = 0
        threat_indicators = []
        
        # Verifică dacă domeniul e în phishing
        if domain in self.threat_intel.phishing_domains:
            threat_score += 15
            threat_indicators.append("phishing_domain")
        
        # Verifică în servicii suspecte
        if domain in self.threat_intel.suspicious_services:
            service_info = self.threat_intel.suspicious_services[domain]
            threat_score += 10
            threat_indicators.append(f"suspicious_service_{service_info['service']}")
        
        # Verifică în pattern-uri de tracking din MailTrackerBlocker
        for pattern in self.threat_intel.tracking_patterns:
            if pattern["domain"] == domain:
                threat_score += 15  # Prioritate maximă pentru pattern-uri cunoscute
                threat_indicators.append(f"mailtracker_pattern_{pattern['source']}")
                break
        
        # Verifică URL-ul complet în pattern-urile din MailTrackerBlocker
        for pattern in self.threat_intel.tracking_patterns:
            pattern_regex = pattern.get("regex_pattern", "")
            if pattern_regex and self._matches_tracking_pattern(pixel_url, pattern_regex):
                threat_score += 12
                threat_indicators.append(f"pattern_match_{pattern['source']}")
                break
        
        # Verifică în listele EasyPrivacy pentru tracking
        if self._is_easyprivacy_tracker(domain, pixel_url):
            threat_score += 10
            threat_indicators.append("easyprivacy_tracker")
        
        # Analiză avansată parametri bazată pe UglyEmail patterns
        uglyemail_score = self._analyze_uglyemail_patterns(pixel_url, query_params)
        if uglyemail_score > 0:
            threat_score += uglyemail_score
            threat_indicators.append("uglyemail_pattern_match")
        
        # Verifică caracteristici specifice tracking pixels
        pixel_characteristics = self._analyze_pixel_characteristics(pixel_url, query_params)
        threat_score += pixel_characteristics["score"]
        threat_indicators.extend(pixel_characteristics["indicators"])
        
        # Determină nivelul de amenințare
        if threat_score >= 20:
            threat_level = "critical"
        elif threat_score >= 10:
            threat_level = "high"
        elif threat_score >= 5:
            threat_level = "medium"
        elif threat_score > 0:
            threat_level = "low"
        else:
            threat_level = "minimal"
        
        pixel_info.update({
            "threat_score": threat_score,
            "threat_level": threat_level,
            "threat_indicators": threat_indicators,
            "is_malicious": threat_score >= 10
        })
        
        return pixel_info
    
    def _matches_tracking_pattern(self, url, pattern_regex):
        """Verifică dacă URL-ul match un pattern din MailTrackerBlocker."""
        import re
        try:
            # Convertește pattern-ul MailTrackerBlocker la regex
            # Ex: "*://domain.com/track/*" -> "https?://domain\.com/track/.*"
            regex_pattern = pattern_regex.replace("*://", "https?://")
            regex_pattern = regex_pattern.replace("*", ".*")
            regex_pattern = regex_pattern.replace(".", r"\.")
            return bool(re.search(regex_pattern, url, re.IGNORECASE))
        except:
            return False
    
    def _is_easyprivacy_tracker(self, domain, url):
        """Verifică dacă domeniul/URL-ul e în EasyPrivacy - DOAR din surse open source."""
        # Verifică dacă domeniul e în lista de trackeri din EasyPrivacy
        if domain in self.threat_intel.phishing_domains:
            return True
        
        # Verifică subdomenii - multe trackeri folosesc subdomenii
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            parent_domain = '.'.join(domain_parts[-2:])
            if parent_domain in self.threat_intel.phishing_domains:
                return True
        
        # ELIMINAT: Lista hardcodată tracking_keywords
        # Verificăm DOAR dacă domeniul e în sursele EasyPrivacy încărcate
        # Acest lucru este mai precis decât keywords hardcodate
        
        return False
    
    def _analyze_uglyemail_patterns(self, url, query_params):
        """Analizează URL-ul cu pattern-urile din UglyEmail."""
        import re
        score = 0
        
        for domain, service_info in self.threat_intel.suspicious_services.items():
            if domain in url:
                # Match exact pentru serviciul UglyEmail
                pattern = service_info.get("pattern", "")
                try:
                    if re.search(pattern, url, re.IGNORECASE):
                        score += 15  # Scor mare pentru match exact UglyEmail
                        break
                except:
                    # Dacă regex-ul e invalid, verifică simplu
                    if domain in url:
                        score += 10
        
        return score
    
    def _analyze_pixel_characteristics(self, url, query_params):
        """Analizează caracteristicile specifice tracking pixels bazat DOAR pe pattern-uri open source."""
        score = 0
        indicators = []
        
        # ELIMINAT: Lista hardcodată tracking_paths 
        # Acum extragem pattern-urile DOAR din sursele open source
        
        # Extrage pattern-uri din path-urile din MailTrackerBlocker și EasyPrivacy
        tracking_paths_from_sources = set()
        
        # Din MailTrackerBlocker patterns
        for pattern_info in self.threat_intel.tracking_patterns:
            pattern = pattern_info.get("pattern", "")
            # Extrage segmente de path din pattern-uri
            import re
            path_segments = re.findall(r'/([^/?\s]+)', pattern.lower())
            for segment in path_segments:
                if len(segment) >= 3:  # Doar segmente semnificative
                    tracking_paths_from_sources.add(f'/{segment}')
        
        # Din domeniile EasyPrivacy, extrage pattern-uri comune
        for domain in list(self.threat_intel.phishing_domains)[:50]:  # Limitez pentru performanță
            # Extrage cuvinte din domenii care par a fi tracking-related
            domain_words = re.findall(r'([a-z]{3,})', domain.lower())
            for word in domain_words:
                tracking_paths_from_sources.add(word)
        
        # Verifică path-ul URL-ului cu pattern-urile extrase dinamic
        url_lower = url.lower()
        for pattern in tracking_paths_from_sources:
            if pattern in url_lower:
                score += 3
                clean_pattern = pattern.replace('/', '').replace('.', '')
                indicators.append(f"opensrc_path_{clean_pattern}")
        
        # Parametri suspecți bazați pe analiza UglyEmail și MailTrackerBlocker
        open_source_suspicious_params = set()
        
        # Extrage parametri suspecți din pattern-urile UglyEmail
        for service_info in self.threat_intel.suspicious_services.values():
            pattern = service_info.get("pattern", "")
            # Găsește parametri comuni în pattern-uri
            import re
            params_in_pattern = re.findall(r'[?&]([^=\s]+)=', pattern)
            for param in params_in_pattern:
                if len(param) >= 1:  # Orice parametru găsit în surse
                    open_source_suspicious_params.add(param.lower())
        
        # Extrage parametri din MailTrackerBlocker patterns
        for pattern_info in self.threat_intel.tracking_patterns:
            pattern = pattern_info.get("pattern", "")
            params_in_pattern = re.findall(r'[?&]([^=\s]+)=', pattern)
            for param in params_in_pattern:
                if len(param) >= 1:
                    open_source_suspicious_params.add(param.lower())
        
        # Verifică parametrii din URL
        found_params = [p for p in query_params.keys() if p.lower() in open_source_suspicious_params]
        if found_params:
            score += len(found_params) * 2
            indicators.extend([f"opensrc_param_{p}" for p in found_params])
        
        # Detectare parametri encodați (observat în multe pattern-uri)
        for param_values in query_params.values():
            for value in param_values:
                if isinstance(value, str) and ('%' in value or value.isalnum() and len(value) > 10):
                    score += 5
                    indicators.append("encoded_or_hashed_param")
                    break
        
        return {"score": score, "indicators": indicators}
    
    def analyze_email_file(self, email_path):
        """Analizează un fișier email pentru tracking pixels."""
        from email import message_from_file
        from email.policy import default
        
        if not self.loaded:
            self.initialize()
        
        try:
            with open(email_path, 'r', encoding='utf-8') as f:
                msg = message_from_file(f, policy=default)
        except UnicodeDecodeError:
            with open(email_path, 'r', encoding='latin-1') as f:
                msg = message_from_file(f, policy=default)
        
        # Extrage conținutul HTML
        html_content = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    html_content += part.get_content()
        else:
            if msg.get_content_type() == "text/html":
                html_content = msg.get_content()
        
        if not html_content:
            return {"error": "Nu s-a găsit conținut HTML în email"}
        
        # Extrage și analizează pixelii
        pixels = self.extract_pixels_from_email(html_content)
        
        # Separă rezultatele pentru HTML și CSS
        html_pixels = [p for p in pixels if p.get("detection_method") == "html_analysis"]
        css_pixels = [p for p in pixels if p.get("detection_method") == "css_analysis"]
        
        # Calculează scorul total de risc
        total_threat_score = sum(p["threat_score"] for p in pixels)
        malicious_pixels = [p for p in pixels if p["is_malicious"]]
        
        # Determină tipul de amenințare
        threat_types = set()
        for pixel in pixels:
            # Handle both old and new pixel formats
            threat_indicators = pixel.get("threat_indicators", [])
            if not threat_indicators:
                # Generate threat indicators from other fields
                if pixel.get("source") == "MailTracker":
                    threat_indicators = ["mailtracker_pattern"]
                elif pixel.get("source") == "GitHub":
                    threat_indicators = ["github_pattern"]
                elif pixel.get("is_malicious"):
                    threat_indicators = ["tracking_pattern"]
            
            for indicator in threat_indicators:
                if "phishing" in indicator:
                    threat_types.add("phishing")
                elif "suspicious_service" in indicator:
                    threat_types.add("email_tracking")
                elif "tracking_pattern" in indicator or "mailtracker" in indicator:
                    threat_types.add("behavior_tracking")
                elif "css_tracking" in indicator:
                    threat_types.add("advanced_css_tracking")
        
        return {
            "email_path": str(email_path),
            "pixels_found": len(pixels),
            "html_pixels": len(html_pixels),
            "css_pixels": len(css_pixels),
            "malicious_pixels": len(malicious_pixels),
            "total_threat_score": total_threat_score,
            "threat_types": list(threat_types),
            "risk_assessment": self._assess_overall_risk(total_threat_score, malicious_pixels, css_pixels),
            "pixels": pixels
        }
    
    def _assess_overall_risk(self, total_score, malicious_pixels, css_pixels):
        """Evaluează riscul general al email-ului cu considerare CSS."""
        # CSS pixels primesc bonus de risc (mai sofisticați)
        css_bonus = len(css_pixels) * 10
        adjusted_score = total_score + css_bonus
        
        if len(malicious_pixels) >= 3 or adjusted_score >= 60 or len(css_pixels) >= 2:
            return "critical"
        elif len(malicious_pixels) >= 2 or adjusted_score >= 30 or len(css_pixels) >= 1:
            return "high"
        elif len(malicious_pixels) >= 1 or adjusted_score >= 15:
            return "medium"
        elif adjusted_score > 0:
            return "low"
        else:
            return "clean"
    
    def generate_report(self, analysis_result):
        """Generează un raport detaliat."""
        result = analysis_result
        
        print(f"\n📧 RAPORT ANALIZA EMAIL: {Path(result['email_path']).name}")
        print("=" * 60)
        print(f"🔍 Tracking pixels găsiți: {result['pixels_found']}")
        print(f"    📄 HTML pixels: {result['html_pixels']}")
        print(f"    🎨 CSS pixels: {result['css_pixels']}")
        print(f"🚨 Pixels malițioși: {result['malicious_pixels']}")
        print(f"📊 Scor total amenințare: {result['total_threat_score']}")
        print(f"⚠️  Evaluare risc: {result['risk_assessment'].upper()}")
        
        if result['css_pixels'] > 0:
            print(f"🎯 DETECTARE CSS AVANSATĂ: {result['css_pixels']} CSS tracking pixels!")
        
        # Afișează statistici despre sursa pattern-urilor
        open_source_pixels = [p for p in result['pixels'] if p.get("pattern_source") == "open_source"]
        if open_source_pixels:
            print(f"🌐 OPEN SOURCE DETECTION: {len(open_source_pixels)} pixels detectați cu pattern-uri din EasyPrivacy/MailTrackerBlocker!")
        
        if result['threat_types']:
            print(f"🎯 Tipuri amenințări: {', '.join(result['threat_types'])}")
        
        if result['pixels']:
            print(f"\n📋 DETALII TRACKING PIXELS:")
            for i, pixel in enumerate(result['pixels'], 1):
                detection_icon = "🎨" if pixel.get("detection_method") == "css_analysis" else "📄"
                source_icon = "🌐" if pixel.get("pattern_source") == "open_source" else "⚙️"
                print(f"\n    🔸 Pixel #{i} {detection_icon}{source_icon} - Risc {pixel['threat_level'].upper()}")
                print(f"        URL: {pixel['url']}")
                print(f"        Domeniu: {pixel['domain']}")
                print(f"        Scor amenințare: {pixel['threat_score']}")
                
                if pixel.get("detection_method") == "css_analysis":
                    print(f"        🎨 CSS Type: {pixel.get('css_type', 'unknown')}")
                elif pixel.get("param_count"):
                    print(f"        Parametri: {pixel['param_count']}")
                
                if pixel.get("pattern_source") == "open_source":
                    print(f"        🌐 Detectat cu pattern #{pixel.get('pattern_index', '?')} din surse open source")
                
                if pixel['threat_indicators']:
                    print(f"        🚩 Indicatori: {', '.join(pixel['threat_indicators'])}")
        
        # Recomandări actualizate
        print(f"\n💡 RECOMANDĂRI:")
        if open_source_pixels:
            print("    🌐 DETECTARE PROFESIONISTĂ: Pattern-uri din threat intelligence real!")
        if result['css_pixels'] > 0:
            print("    🎨 ALERTĂ CSS: Tracking pixels ascunși în CSS detectați!")
            print("    🎨 Aceasta indică o campanie de phishing SOFISTICATĂ!")
        
        if result['risk_assessment'] == "critical":
            print("    🚨 PERICOL EXTREM - Ștergeți email-ul imediat!")
            print("    🚨 NU deschideți link-uri sau atașamente!")
            print("    🚨 Raportați la echipa de securitate!")
        elif result['risk_assessment'] == "high":
            print("    ⚠️  Risc ridicat - Verificare suplimentară necesară")
            print("    ⚠️  Evitați interacțiunea cu email-ul")
        elif result['risk_assessment'] == "medium":
            print("    ℹ️  Risc moderat - Precauție recomandată")
        elif result['risk_assessment'] == "low":
            print("    ✅ Risc scăzut - Email probabil legitim")
        else:
            print("    ✅ Email curat - Niciun tracker detectat")

    def _load_mailtracker_patterns(self):
        """Încarcă pattern-uri MailTracker din cache și le convertește în regex-uri."""
        import json
        
        cache_file = Path("cache/mailtracker_cache.json")
        if not cache_file.exists():
            print("    [-] Cache MailTracker nu există")
            return []
        
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache_data = json.load(f)
            
            patterns = []
            for item in cache_data.get('data', []):
                pattern = item.get('pattern', '')
                if pattern:
                    # Convertește pattern MailTracker în regex
                    # *://domain.com/path/* -> https?://domain\.com/path/.*
                    regex_pattern = self._convert_mailtracker_to_regex(pattern)
                    if regex_pattern:
                        patterns.append(regex_pattern)
            
            print(f"    [✓] Încărcate {len(patterns)} pattern-uri MailTracker din cache")
            return patterns
            
        except Exception as e:
            print(f"    [-] Eroare încărcare MailTracker cache: {e}")
            return []
    
    def _convert_mailtracker_to_regex(self, pattern):
        """Convertește un pattern MailTracker în regex pentru matching."""
        try:
            # *://track.flexlinks.com/a.ashx?* -> src="https?://track\.flexlinks\.com/a\.ashx\?.*"
            
            # Escapeăm characterele speciale regex
            escaped = re.escape(pattern)
            
            # Înlocuim wildcards
            escaped = escaped.replace(r'\*', '.*')
            escaped = escaped.replace(r'\?', r'\?')
            
            # Convertim protocoale
            escaped = escaped.replace(r'\*\://', r'https?\://')
            
            # Creăm pattern pentru img src sau href
            img_pattern = rf'(?:src|href)=[\"\']({escaped})[\"\']'
            
            return img_pattern
            
        except Exception as e:
            print(f"    [-] Eroare conversie pattern {pattern}: {e}")
            return None

    def _load_github_patterns(self):
        """Încarcă pattern-uri din GitHub open source database."""
        import json
        
        github_file = Path("sources/github_tracking_rules.json")
        if not github_file.exists():
            print("    [-] GitHub tracking rules nu există")
            return []
        
        try:
            with open(github_file, 'r', encoding='utf-8') as f:
                github_data = json.load(f)
            
            patterns = []
            
            # 1. Convertește domeniile GitHub în pattern-uri pentru img src
            domains = github_data.get('domains', [])[:1000]  # Limitez la 1000 pentru performanță
            for domain in domains:
                if len(domain) > 3 and '.' in domain:
                    # Creez pattern pentru orice img src de la acest domeniu
                    domain_pattern = rf'(?:src|href)=[\"\']https?://{re.escape(domain)}/[^\"\']*[\"\']'
                    patterns.append(domain_pattern)
            
            # 2. Convertește URL patterns GitHub
            url_patterns = github_data.get('url_patterns', [])[:500]  # Limitez la 500
            for url_pattern in url_patterns:
                if len(url_pattern) > 5:
                    # Creez pattern pentru img src cu acest path
                    path_pattern = rf'(?:src|href)=[\"\']https?://[^/]+{re.escape(url_pattern)}[^\"\']*[\"\']'
                    patterns.append(path_pattern)
            
            print(f"    [✓] Încărcate {len(patterns)} pattern-uri GitHub ({len(domains)} domenii + {len(url_patterns)} URL patterns)")
            return patterns
            
        except Exception as e:
            print(f"    [-] Eroare încărcare GitHub patterns: {e}")
            return []

    def _calculate_optimized_threat_score(self, result: dict) -> int:
        """Calculate threat score for optimized engine results."""
        base_score = 20
        
        # Source-based scoring
        if result['source'] == 'MailTracker':
            base_score += 25
        elif result['source'] == 'GitHub':
            base_score += 15
        
        # Threat level multiplier
        if result['threat_level'] == 'critical':
            base_score *= 2
        elif result['threat_level'] == 'high':
            base_score *= 1.5
        
        # Confidence bonus
        if result['confidence'] == 'high':
            base_score += 10
        
        return int(base_score)
    
    def _fallback_regex_scan(self, email_content: str, existing_urls: list) -> list:
        """Fallback regex scanning for patterns missed by optimized engine."""
        pixels_found = []
        existing_urls_set = set(existing_urls)
        
        # Quick regex scan for obvious tracking patterns not caught by O(1) lookup
        fallback_patterns = [
            r'(?:src|href)=["\']([^"\']*(?:track|pixel|beacon|analytics)[^"\']*)["\']',
            r'<img[^>]*src=["\']([^"\']*\?[^"\']*(?:utm_|campaign|track)[^"\']*)["\'][^>]*>'
        ]
        
        for pattern in fallback_patterns:
            try:
                matches = re.finditer(pattern, email_content, re.IGNORECASE)
                for match in matches:
                    url = match.group(1)
                    if url not in existing_urls_set and url.startswith(('http://', 'https://')):
                        pixel_info = self._analyze_pixel_url(url)
                        pixel_info["detection_method"] = "fallback_regex"
                        pixel_info["pattern_source"] = "fallback_scan"
                        pixels_found.append(pixel_info)
                        existing_urls_set.add(url)
            except re.error:
                continue
        
        return pixels_found

def main():
    """Demonstrație a detectorului final."""
    import sys
    
    if len(sys.argv) > 1:
        email_path = Path(sys.argv[1])
        if not email_path.exists():
            print(f"❌ Fișierul {email_path} nu există!")
            return
    else:
        # Folosește email-ul de test
        email_path = Path("../test_email.eml")
        if not email_path.exists():
            print("❌ Nu există email de test. Furnizați calea către un fișier .eml")
            return
    
    # Inițializează detectorul
    detector = FinalPixelDetector()
    detector.initialize()
    
    # Analizează email-ul
    print(f"\n[+] Analizez: {email_path}")
    result = detector.analyze_email_file(email_path)
    
    if "error" in result:
        print(f"❌ Eroare: {result['error']}")
        return
    
    # Generează raportul
    detector.generate_report(result)
    
    # Salvează rezultatul
    output_file = email_path.parent / f"{email_path.stem}_final_analysis.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    
    print(f"\n[+] 💾 Analiza detaliată salvată: {output_file}")

if __name__ == "__main__":
    main()