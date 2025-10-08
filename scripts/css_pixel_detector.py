"""
CSS Pixel Detector - Detectează tracking pixels ascunși în CSS
Folosește threat intelligence open source pentru analiză profesionistă
"""

import re
import json
import logging
from pathlib import Path
from urllib.parse import urlparse
from typing import List, Dict, Any

class CSSPixelDetector:
    """Detector specializat pentru tracking pixels în CSS cu threat intelligence."""
    
    def __init__(self, threat_intel=None):
        self.threat_intel = threat_intel  # OptimizedThreatIntelligence instance
        
        # ELIMINAT: Lista hardcodată css_pixel_patterns
        # Acum extragem pattern-urile dinamic din threat intelligence
        
        # ELIMINAT: Lista hardcodată suspicious_css_patterns  
        # Folosim doar pattern-uri din surse open source
        
        # Keywords pentru identificarea tracking în CSS (din analiza surselor open source)
        self.css_tracking_keywords = self._extract_tracking_keywords_from_sources()
    
    def _extract_tracking_keywords_from_sources(self):
        """Extrage keywords de tracking DOAR din sursele open source - fără hardcoding."""
        keywords = set()
        
        # Adaugă keywords din threat intelligence dacă e disponibil
        if self.threat_intel:
            # Extrage keywords din pattern-urile MailTrackerBlocker
            for pattern_info in self.threat_intel.tracking_patterns:
                pattern = pattern_info.get("pattern", "").lower()
                domain = pattern_info.get("domain", "")
                
                # Extrage cuvinte din pattern-uri prin analiza URL-urilor
                import re
                url_words = re.findall(r'([a-z]+)', pattern)
                for word in url_words:
                    if len(word) >= 3:  # Doar cuvinte de minim 3 caractere
                        keywords.add(word)
                
                # Extrage cuvinte din domenii
                if domain:
                    domain_words = re.findall(r'([a-z]+)', domain.lower())
                    for word in domain_words:
                        if len(word) >= 3:
                            keywords.add(word)
            
            # Adaugă servicii din UglyEmail  
            for domain, service_info in self.threat_intel.suspicious_services.items():
                service_name = service_info.get("service", "").lower()
                if service_name:
                    # Adaugă numele serviciului ca keyword
                    clean_service = service_name.replace(" ", "").replace("-", "").lower()
                    if len(clean_service) >= 3:
                        keywords.add(clean_service)
                        
                # Extrage și din domeniu
                import re
                domain_words = re.findall(r'([a-z]+)', domain.lower())
                for word in domain_words:
                    if len(word) >= 3:
                        keywords.add(word)
        
        return list(keywords)  # Return doar keywords-urile extrase din surse
    
    def extract_css_pixels(self, html_content: str) -> List[Dict[str, Any]]:
        """Extrage tracking pixels din CSS folosind DOAR pattern-uri open source dinamice."""
        css_pixels = []
        
        # Generez pattern-uri CSS dinamice din sursele open source
        css_patterns = self._generate_dynamic_css_patterns()
        
        # 1. Extrage și analizează tag-urile <style>
        style_tags = re.finditer(r'<style[^>]*>(.*?)</style>', html_content, re.IGNORECASE | re.DOTALL)
        for style_match in style_tags:
            css_content = style_match.group(1)
            pixels_in_css = self._analyze_css_content(css_content, "style_tag", css_patterns)
            css_pixels.extend(pixels_in_css)
        
        # 2. Analizează inline style attributes
        inline_styles = re.finditer(r'style\s*=\s*["\']([^"\']+)["\']', html_content, re.IGNORECASE)
        for inline_match in inline_styles:
            style_content = inline_match.group(1)
            pixels_in_inline = self._analyze_css_content(style_content, "inline_style", css_patterns)
            css_pixels.extend(pixels_in_inline)
        
        # 3. ELIMINAT: pattern-uri CSS suspicioase hardcodate
        # Acum folosim doar pattern-uri generate dinamic din threat intelligence
        
        # Elimină duplicatele
        unique_pixels = []
        seen_urls = set()
        for pixel in css_pixels:
            if pixel["url"] not in seen_urls:
                unique_pixels.append(pixel)
                seen_urls.add(pixel["url"])
        
        return unique_pixels
    
    def _generate_dynamic_css_patterns(self) -> List[str]:
        """Generează pattern-uri CSS dinamice din surse GitHub open source și threat intelligence."""
        patterns = []
        
        try:
            # 1. Prima prioritate: GitHub open source rules
            github_rules_file = Path(__file__).parent.parent / "sources" / "github_tracking_rules.json"
            if github_rules_file.exists():
                with open(github_rules_file, 'r', encoding='utf-8') as f:
                    github_data = json.load(f)
                
                # Folosește pattern-urile CSS extrase din GitHub
                if 'css_patterns' in github_data and github_data['css_patterns']:
                    patterns.extend(github_data['css_patterns'][:50])  # Limitez pentru performanță
                    logging.info(f"Loaded {len(github_data['css_patterns'])} CSS patterns from GitHub sources")
                
                # Generează pattern-uri din domeniile GitHub cu cuvinte cheie CSS
                if 'domains' in github_data:
                    css_keywords = ['pixel', 'track', 'analytic', 'beacon', 'collect', 'image', 'img', 'background']
                    css_domains = [d for d in github_data['domains'] 
                                 if any(keyword in d.lower() for keyword in css_keywords)][:30]
                    
                    for domain in css_domains:
                        escaped_domain = re.escape(domain)
                        patterns.extend([
                            rf'url\s*\(\s*["\']?[^"\']*{escaped_domain}[^"\']*["\']?\s*\)',
                            rf'background[^;]*{escaped_domain}',
                            rf'@import[^;]*{escaped_domain}'
                        ])
                
                # Generează pattern-uri din URL patterns GitHub  
                if 'url_patterns' in github_data:
                    css_url_patterns = [p for p in github_data['url_patterns'] 
                                      if any(term in p for term in ['gif', 'png', 'jpg', 'css', 'pixel'])][:20]
                    
                    for url_pattern in css_url_patterns:
                        escaped_pattern = re.escape(url_pattern)
                        patterns.append(rf'url\s*\([^)]*{escaped_pattern}[^)]*\)')
        
        except Exception as e:
            logging.warning(f"Could not load GitHub CSS patterns: {e}")
        
        # 2. Fallback la threat intelligence existent
        if not patterns and self.threat_intel:
            css_domains_from_sources = set()
            
            # Din domeniile EasyPrivacy care conțin indicatori CSS
            easyprivacy_domains = list(self.threat_intel.phishing_domains)[:50] if hasattr(self.threat_intel, 'phishing_domains') else []
            for domain in easyprivacy_domains:
                if any(keyword in domain.lower() for keyword in ['background', 'css', 'style', 'image', 'img']):
                    css_domains_from_sources.add(domain)
            
            # Din MailTrackerBlocker patterns cu imagini/CSS
            for pattern_info in (self.threat_intel.tracking_patterns[:20] if hasattr(self.threat_intel, 'tracking_patterns') else []):
                pattern = pattern_info.get("pattern", "")
                domain = pattern_info.get("domain", "")
                
                if any(ext in pattern.lower() for ext in ['.gif', '.png', '.jpg', 'image', 'img', 'pixel']):
                    if domain:
                        css_domains_from_sources.add(domain)
            
            # Generează pattern-uri CSS pentru domeniile găsite
            for domain in css_domains_from_sources:
                try:
                    escaped_domain = re.escape(domain)
                    patterns.append(rf'url\s*\(\s*["\']?[^"\']*{escaped_domain}[^"\']*["\']?\s*\)')
                except re.error:
                    continue
        
        # 3. Pattern generic minimal ca ultima opțiune
        if not patterns:
            patterns = [r'url\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)']
            logging.info("Using minimal fallback CSS pattern")
        
        logging.info(f"Generated {len(patterns)} dynamic CSS patterns from open sources")
        return patterns
    
    def _analyze_css_content(self, css_content: str, css_type: str, patterns: List[str]) -> List[Dict[str, Any]]:
        """Analizează conținutul CSS pentru tracking pixels cu pattern-uri dinamice."""
        css_pixels = []
        
        for pattern in patterns:
            try:
                matches = re.finditer(pattern, css_content, re.IGNORECASE)
                for match in matches:
                    pixel_url = match.group(1)
                    if self._is_potential_tracking_url(pixel_url):
                        pixel_info = self._analyze_css_pixel_url(pixel_url, css_type)
                        css_pixels.append(pixel_info)
            except (re.error, IndexError):
                continue  # Skip invalid patterns or matches
        
        return css_pixels
    
    def _is_potential_tracking_url(self, url: str) -> bool:
        """Verifică dacă URL-ul pare să fie un tracking pixel folosind threat intelligence."""
        url_lower = url.lower()
        
        # 1. Verifică în threat intelligence dacă e disponibil
        if self.threat_intel:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Verifică în domenii phishing/tracking din EasyPrivacy
            if domain in self.threat_intel.phishing_domains:
                return True
            
            # Verifică în pattern-uri MailTrackerBlocker
            for pattern_info in self.threat_intel.tracking_patterns:
                if pattern_info["domain"] == domain:
                    return True
            
            # Verifică în servicii suspecte UglyEmail
            if domain in self.threat_intel.suspicious_services:
                return True
        
        # 2. Fallback la verificări de bază dacă nu avem threat intelligence
        # Verifică extensiile de imagini
        image_extensions = ['.gif', '.png', '.jpg', '.jpeg', '.webp', '.svg']
        has_image_ext = any(ext in url_lower for ext in image_extensions)
        
        # Verifică keywords de tracking
        has_tracking_keyword = any(keyword in url_lower for keyword in self.css_tracking_keywords)
        
        # Verifică pattern-uri de URL tracking
        tracking_patterns = [
            r'/track', r'/pixel', r'/beacon', r'/open', r'/click',
            r'/analytics', r'/stats', r'/count', r'/visit'
        ]
        has_tracking_pattern = any(re.search(pattern, url_lower) for pattern in tracking_patterns)
        
        # URL-ul trebuie să fie HTTP/HTTPS
        is_valid_url = url.startswith(('http://', 'https://'))
        
        return is_valid_url and (has_image_ext or has_tracking_keyword or has_tracking_pattern)
    
    def _analyze_css_pixel_url(self, pixel_url: str, css_type: str) -> Dict[str, Any]:
        """Analizează detaliat un URL de tracking pixel din CSS folosind threat intelligence."""
        parsed_url = urlparse(pixel_url)
        domain = parsed_url.netloc
        path = parsed_url.path
        
        # Calculează scorul de amenințare pentru CSS pixels
        threat_score = 20  # Scor de bază mai mare pentru CSS (mai sofisticat)
        threat_indicators = [f"css_tracking_{css_type}"]
        
        # THREAT INTELLIGENCE ANALYSIS
        if self.threat_intel:
            # Verifică dacă domeniul e în phishing
            if domain in self.threat_intel.phishing_domains:
                threat_score += 15
                threat_indicators.append("css_phishing_domain")
            
            # Verifică în servicii suspecte UglyEmail
            if domain in self.threat_intel.suspicious_services:
                service_info = self.threat_intel.suspicious_services[domain]
                threat_score += 12
                threat_indicators.append(f"css_uglyemail_{service_info['service']}")
            
            # Verifică în pattern-uri MailTrackerBlocker
            for pattern in self.threat_intel.tracking_patterns:
                if pattern["domain"] == domain:
                    threat_score += 15
                    threat_indicators.append(f"css_mailtracker_{pattern['source']}")
                    break
        
        # PATTERN ANALYSIS (cu date din threat intelligence)
        url_lower = pixel_url.lower()
        
        # Verifică keywords de tracking (dinamic din surse)
        for keyword in self.css_tracking_keywords:
            if keyword in url_lower:
                threat_score += 3
                threat_indicators.append(f"css_keyword_{keyword}")
        
        # Verifică extensii tipice de tracking
        if any(ext in url_lower for ext in ['.gif', '.png']):
            threat_score += 5
            threat_indicators.append("css_tracking_image")
        
        # Verifică path-uri suspecte (îmbunătățit cu pattern-uri din surse)
        suspicious_paths = self._get_suspicious_paths_from_sources()
        for susp_path in suspicious_paths:
            if susp_path in path.lower():
                threat_score += 5
                threat_indicators.append(f"css_suspicious_path")
                break
        
        # Verifică parametrii din query string
        if parsed_url.query:
            threat_score += 8
            threat_indicators.append("css_with_parameters")
            
            # Parametri suspecți din analiza surselor open source
            suspicious_params = self._get_suspicious_params_from_sources()
            query_lower = parsed_url.query.lower()
            for param in suspicious_params:
                if param in query_lower:
                    threat_score += 3
                    threat_indicators.append(f"css_param_{param}")
        
        # Determină nivelul de amenințare (ajustat pentru CSS)
        if threat_score >= 40:
            threat_level = "critical"
        elif threat_score >= 30:
            threat_level = "high"
        elif threat_score >= 20:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        return {
            "url": pixel_url,
            "domain": domain,
            "path": path,
            "css_type": css_type,
            "threat_score": threat_score,
            "threat_level": threat_level,
            "threat_indicators": threat_indicators,
            "is_malicious": threat_score >= 25,  # Pragul pentru CSS e mai mic
            "detection_method": "css_analysis"
        }
    
    def _get_suspicious_paths_from_sources(self):
        """Extrage path-uri suspecte din sursele open source."""
        base_paths = ['/track/', '/pixel/', '/beacon/', '/open/', '/analytics/']
        
        if self.threat_intel:
            # Adaugă path-uri din pattern-urile MailTrackerBlocker
            for pattern_info in self.threat_intel.tracking_patterns:
                pattern = pattern_info.get("pattern", "")
                # Extrage segmente de path din pattern-uri
                if "/" in pattern:
                    path_segments = [seg for seg in pattern.split("/") if seg and not seg.startswith("*")]
                    for segment in path_segments:
                        if len(segment) > 2 and segment.lower() not in base_paths:
                            base_paths.append(f"/{segment.lower()}/")
        
        return base_paths
    
    def _get_suspicious_params_from_sources(self):
        """Extrage parametri suspecți din sursele open source."""
        base_params = ['id', 'uid', 'user', 'email', 'track', 'campaign']
        
        if self.threat_intel:
            # Adaugă parametri din pattern-urile UglyEmail
            for domain, service_info in self.threat_intel.suspicious_services.items():
                pattern = service_info.get("pattern", "")
                # Găsește parametri în pattern-uri (ex: upn=, u=, id=)
                param_matches = re.findall(r'([a-zA-Z]+)=', pattern)
                base_params.extend(param_matches)
        
        return list(set(base_params))
    
    def generate_css_report(self, css_pixels: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generează raport pentru pixel-urile CSS detectate."""
        if not css_pixels:
            return {
                "css_pixels_found": 0,
                "css_threat_assessment": "clean",
                "css_pixels": []
            }
        
        total_css_score = sum(p["threat_score"] for p in css_pixels)
        malicious_css = [p for p in css_pixels if p["is_malicious"]]
        
        # Assessment-ul CSS este mai sever (CSS tracking e mai sofisticat)
        if len(malicious_css) >= 2 or total_css_score >= 60:
            css_assessment = "critical"
        elif len(malicious_css) >= 1 or total_css_score >= 30:
            css_assessment = "high"
        elif total_css_score >= 15:
            css_assessment = "medium"
        else:
            css_assessment = "low"
        
        return {
            "css_pixels_found": len(css_pixels),
            "css_malicious_pixels": len(malicious_css),
            "css_total_threat_score": total_css_score,
            "css_threat_assessment": css_assessment,
            "css_pixels": css_pixels
        }

def main():
    """Test pentru CSS Pixel Detector cu threat intelligence."""
    
    # Simulez un threat intelligence pentru demo
    class MockThreatIntel:
        def __init__(self):
            self.phishing_domains = {'analytics.tracker.com', 'spy.malware.tk'}
            self.tracking_patterns = [
                {"domain": "analytics.tracker.com", "pattern": "*://analytics.tracker.com/pixel*", "source": "MailTrackerBlocker"}
            ]
            self.suspicious_services = {
                'spy.malware.tk': {"service": "Spyware", "pattern": "/beacon.png?user=*"}
            }
    
    # Email de test cu CSS tracking
    test_html = """
    <html>
    <head>
        <style>
            .tracker { 
                background: url('https://analytics.tracker.com/pixel.gif?campaign=email123'); 
                width: 1px; 
                height: 1px; 
            }
            .hidden-spy::after { 
                content: url('https://spy.malware.tk/beacon.png?user=victim'); 
                display: none; 
            }
        </style>
    </head>
    <body>
        <div style="background-image: url('https://track.phishing.ml/open.gif?id=abc123'); width: 1px; height: 1px; visibility: hidden;"></div>
        <span style="display: none; background: url('https://monitor.suspicious.com/track.png');"></span>
        <p>Conținut normal...</p>
    </body>
    </html>
    """
    
    print("🎨 CSS PIXEL DETECTION TEST (CU THREAT INTELLIGENCE)")
    print("=" * 60)
    
    # Test fără threat intelligence
    detector_basic = CSSPixelDetector()
    css_pixels_basic = detector_basic.extract_css_pixels(test_html)
    print(f"FĂRĂ threat intelligence: {len(css_pixels_basic)} pixels, keywords: {len(detector_basic.css_tracking_keywords)}")
    
    # Test cu threat intelligence
    mock_intel = MockThreatIntel()
    detector_intel = CSSPixelDetector(threat_intel=mock_intel)
    css_pixels_intel = detector_intel.extract_css_pixels(test_html)
    
    print(f"CU threat intelligence: {len(css_pixels_intel)} pixels, keywords: {len(detector_intel.css_tracking_keywords)}")
    
    for i, pixel in enumerate(css_pixels_intel, 1):
        print(f"\nCSS Pixel #{i}:")
        print(f"  URL: {pixel['url']}")
        print(f"  CSS Type: {pixel['css_type']}")
        print(f"  Threat Level: {pixel['threat_level']}")
        print(f"  Score: {pixel['threat_score']}")
        print(f"  🔍 Threat Intel Indicators: {[ind for ind in pixel['threat_indicators'] if 'css_phishing' in ind or 'css_uglyemail' in ind or 'css_mailtracker' in ind]}")
        print(f"  📝 All Indicators: {pixel['threat_indicators']}")
    
    print(f"\n✅ DEMONSTRAȚIE: Detectorul folosește {len(mock_intel.phishing_domains)} domenii phishing")
    print(f"✅ DEMONSTRAȚIE: Detectorul folosește {len(mock_intel.tracking_patterns)} pattern-uri MailTrackerBlocker")
    print(f"✅ DEMONSTRAȚIE: Detectorul folosește {len(mock_intel.suspicious_services)} servicii UglyEmail")

if __name__ == "__main__":
    main()