"""
Pattern Extractor - Extrage pattern-uri de tracking din sursele open source
Elimină dependența de pattern-uri hardcodate
"""

import re
from typing import List, Dict, Set
from pathlib import Path

class OpenSourcePatternExtractor:
    """Extrage pattern-uri din sursele open source pentru detectarea tracking pixels."""
    
    def __init__(self, sources_dir="sources"):
        self.sources_dir = Path(sources_dir)
        self.extracted_patterns = {
            "pixel_paths": set(),      # /pixel, /track, etc.
            "pixel_files": set(),      # pixel.gif, track.png, etc.
            "pixel_params": set(),     # ?pixel=, &track=, etc.
            "img_dimensions": set(),   # 1x1, 1px, etc.
            "css_properties": set()    # background, mask, etc.
        }
    
    def extract_patterns_from_easyprivacy(self):
        """Extrage pattern-uri de tracking din EasyPrivacy."""
        easyprivacy_path = self.sources_dir / "easyprivacy.txt"
        
        if not easyprivacy_path.exists():
            print(f"[-] Nu găsesc {easyprivacy_path}")
            return
        
        print("[+] Extrag pattern-uri din EasyPrivacy...")
        
        with open(easyprivacy_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('!') or line.startswith('['):
                continue
            
            # Extrage pattern-uri pentru pixel files
            pixel_file_matches = re.findall(r'/([^/\s]*(?:pixel|track|beacon|1x1|1px)[^/\s]*\.(?:gif|png|jpg|jpeg))', line, re.IGNORECASE)
            for match in pixel_file_matches:
                self.extracted_patterns["pixel_files"].add(match.lower())
            
            # Extrage pattern-uri pentru pixel paths
            pixel_path_matches = re.findall(r'(/[^?\s]*(?:pixel|track|beacon|analytics|stats)[^?\s]*)', line, re.IGNORECASE)
            for match in pixel_path_matches:
                if len(match) < 50:  # Evită pattern-uri prea lungi
                    self.extracted_patterns["pixel_paths"].add(match.lower())
            
            # Extrage parametri de tracking
            param_matches = re.findall(r'[?&]([^=\s]*(?:pixel|track|beacon|id|uid|user)[^=\s]*=)', line, re.IGNORECASE)
            for match in param_matches:
                self.extracted_patterns["pixel_params"].add(match.lower().replace('=', ''))
            
            # Extrage dimensiuni specifice
            dimension_matches = re.findall(r'([0-9]+x[0-9]+|[0-9]+px)', line, re.IGNORECASE)
            for match in dimension_matches:
                if '1' in match:  # Doar dimensiuni care conțin 1 (tracking pixels)
                    self.extracted_patterns["img_dimensions"].add(match.lower())
    
    def extract_patterns_from_mailtracker(self):
        """Extrage pattern-uri din MailTrackerBlocker."""
        mailtracker_path = self.sources_dir / "mailtrackerblocker.json"
        
        if not mailtracker_path.exists():
            print(f"[-] Nu găsesc {mailtracker_path}")
            return
        
        print("[+] Extrag pattern-uri din MailTrackerBlocker...")
        
        import json
        with open(mailtracker_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        for entry in data:
            if isinstance(entry, dict) and "include" in entry:
                for pattern in entry["include"]:
                    # Extrage paths din pattern-uri
                    path_matches = re.findall(r'://[^/]+(/[^?\s]*)', pattern)
                    for path in path_matches:
                        if any(keyword in path.lower() for keyword in ['track', 'pixel', 'open', 'click']):
                            self.extracted_patterns["pixel_paths"].add(path.lower())
                    
                    # Extrage file names
                    file_matches = re.findall(r'/([^/?\s]+\.(?:gif|png|jpg|jpeg|php))', pattern)
                    for filename in file_matches:
                        if any(keyword in filename.lower() for keyword in ['track', 'pixel', 'open', 'click']):
                            self.extracted_patterns["pixel_files"].add(filename.lower())
    
    def generate_dynamic_patterns(self) -> Dict[str, List[str]]:
        """Generează pattern-uri regex dinamice din datele extrase."""
        
        # Extrage datele din surse
        self.extract_patterns_from_easyprivacy()
        self.extract_patterns_from_mailtracker()
        
        # Generează pattern-uri regex
        patterns = {
            "html_img_patterns": [],
            "css_background_patterns": [],
            "url_tracking_patterns": []
        }
        
        # 1. Pattern-uri HTML pentru imagini cu dimensiuni suspecte
        dimension_pattern = "|".join(self.extracted_patterns["img_dimensions"]) if self.extracted_patterns["img_dimensions"] else "1px|1x1"
        patterns["html_img_patterns"].extend([
            rf'<img[^>]*src=["\']([^"\']*)["\'][^>]*(?:width=["\']({dimension_pattern})["\']|height=["\']({dimension_pattern})["\'])',
            rf'<img[^>]*(?:width=["\']({dimension_pattern})["\']|height=["\']({dimension_pattern})["\'])[^>]*src=["\']([^"\']*)["\']',
            rf'<img[^>]*style=["\'][^"\']*(?:width:\s*({dimension_pattern})|height:\s*({dimension_pattern}))[^"\']*["\'][^>]*src=["\']([^"\']*)["\']',
        ])
        
        # 2. Pattern-uri pentru URL-uri cu paths suspecte
        if self.extracted_patterns["pixel_paths"]:
            paths_escaped = [re.escape(path) for path in self.extracted_patterns["pixel_paths"]]
            paths_pattern = "|".join(paths_escaped[:20])  # Limitează la primele 20
            patterns["url_tracking_patterns"].append(
                rf'https?://[^/\s]+({paths_pattern})[^?\s]*\.(?:gif|png|jpg|jpeg)'
            )
        
        # 3. Pattern-uri pentru files suspecte
        if self.extracted_patterns["pixel_files"]:
            files_escaped = [re.escape(filename) for filename in self.extracted_patterns["pixel_files"]]
            files_pattern = "|".join(files_escaped[:20])
            patterns["url_tracking_patterns"].append(
                rf'https?://[^/\s]+/[^/\s]*({files_pattern})'
            )
        
        # 4. Pattern-uri CSS (păstrăm structura de bază dar îmbunătățim)
        patterns["css_background_patterns"] = [
            r'background\s*:\s*[^;]*url\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)',
            r'background-image\s*:\s*url\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)',
            r'::?(?:before|after)\s*\{[^}]*background[^}]*url\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)',
            r'mask\s*:\s*[^;]*url\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)',
            r'mask-image\s*:\s*url\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)',
        ]
        
        return patterns
    
    def get_statistics(self) -> Dict[str, int]:
        """Returnează statistici despre pattern-urile extrase."""
        return {
            "pixel_paths": len(self.extracted_patterns["pixel_paths"]),
            "pixel_files": len(self.extracted_patterns["pixel_files"]),
            "pixel_params": len(self.extracted_patterns["pixel_params"]),
            "img_dimensions": len(self.extracted_patterns["img_dimensions"]),
            "total_patterns": sum(len(patterns) for patterns in self.extracted_patterns.values())
        }
    
    def show_extracted_patterns(self):
        """Afișează pattern-urile extrase pentru debugging."""
        print("\n🔍 PATTERN-URI EXTRASE DIN SURSE OPEN SOURCE:")
        print("=" * 60)
        
        for category, patterns in self.extracted_patterns.items():
            if patterns:
                print(f"\n📂 {category.upper()} ({len(patterns)} pattern-uri):")
                for pattern in sorted(list(patterns))[:10]:  # Afișează primele 10
                    print(f"    {pattern}")
                if len(patterns) > 10:
                    print(f"    ... și încă {len(patterns) - 10} pattern-uri")

def main():
    """Demo pentru Pattern Extractor."""
    print("🔍 OPEN SOURCE PATTERN EXTRACTOR")
    print("=" * 50)
    
    extractor = OpenSourcePatternExtractor()
    patterns = extractor.generate_dynamic_patterns()
    stats = extractor.get_statistics()
    
    print(f"\n📊 STATISTICI EXTRAGERE:")
    for key, value in stats.items():
        print(f"    {key}: {value}")
    
    print(f"\n🎯 PATTERN-URI REGEX GENERATE:")
    for category, pattern_list in patterns.items():
        print(f"\n{category}:")
        for i, pattern in enumerate(pattern_list, 1):
            print(f"    {i}. {pattern}")
    
    # Afișează pattern-urile raw extrase
    extractor.show_extracted_patterns()

if __name__ == "__main__":
    main()