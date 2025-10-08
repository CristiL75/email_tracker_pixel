#!/usr/bin/env python3
"""
Professional Email Tracking Pixel Detector
Enterprise-grade detection using open source threat intelligence

Detectează tracking pixels în email-uri folosind surse open source:
- EasyPrivacy (51,000+ domenii phishing)  
- MailTrackerBlocker (185+ pattern-uri tracking)
- UglyEmail (servicii tracking majore)
- PhishTank (domenii phishing în timp real)

Autor: Professional Security Implementation
Data: Octombrie 2025
"""

from scripts.final_pixel_detector import FinalPixelDetector
import sys
from pathlib import Path

def main():
    """Main entry point pentru detectorul de tracking pixels."""
    
    if len(sys.argv) < 2:
        print("📧 PROFESSIONAL EMAIL TRACKING PIXEL DETECTOR")
        print("=" * 60)
        print("Detectare bazată pe threat intelligence open source")
        print()
        print("Utilizare:")
        print(f"    python {sys.argv[0]} <cale_catre_email.eml>")
        print()
        print("Exemple:")
        print(f"    python {sys.argv[0]} test_email.eml")
        print(f"    python {sys.argv[0]} test_emails/phishing_sample.eml")
        print()
        print("Surse open source integrate:")
        print("    🔴 EasyPrivacy - 51,000+ domenii phishing")
        print("    🔍 MailTrackerBlocker - 185+ pattern-uri tracking")
        print("    ⚠️  UglyEmail - servicii tracking majore")
        print("    🎯 PhishTank - threat intelligence în timp real")
        return
    
    email_path = Path(sys.argv[1])
    
    if not email_path.exists():
        print(f"❌ Eroare: Fișierul {email_path} nu există!")
        return
    
    if not email_path.suffix.lower() in ['.eml', '.msg']:
        print(f"⚠️  Avertisment: {email_path} nu pare să fie un fișier email (.eml/.msg)")
        response = input("Continuați? (y/N): ")
        if response.lower() != 'y':
            return
    
    print("🚀 Inițializez Professional Email Tracking Pixel Detector...")
    print()
    
    try:
        # Inițializează detectorul
        detector = FinalPixelDetector()
        detector.initialize()
        
        # Analizează email-ul
        print(f"\n🔍 Analizez: {email_path}")
        result = detector.analyze_email_file(email_path)
        
        if "error" in result:
            print(f"❌ Eroare: {result['error']}")
            return
        
        # Generează raportul
        detector.generate_report(result)
        
        # Salvează rezultatul
        output_file = email_path.parent / f"{email_path.stem}_professional_analysis.json"
        import json
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 Analiza detaliată salvată: {output_file}")
        
        # Afișează statistici finale
        print(f"\n📊 SUMAR FINAL:")
        print(f"    🎯 Email analizat: {email_path.name}")
        print(f"    🔍 Pixels detectați: {result['pixels_found']}")
        print(f"    🚨 Pixels malițioși: {result['malicious_pixels']}")
        print(f"    📊 Scor amenințare: {result['total_threat_score']}")
        print(f"    ⚠️  Nivel risc: {result['risk_assessment'].upper()}")
        
        if result['css_pixels'] > 0:
            print(f"    🎨 CSS pixels avansați: {result['css_pixels']}")
        
        if result['threat_types']:
            print(f"    🎯 Tipuri amenințări: {', '.join(result['threat_types'])}")
        
    except KeyboardInterrupt:
        print("\n\n⏹️  Analiza întreruptă de utilizator.")
    except Exception as e:
        print(f"\n❌ Eroare neașteptată: {e}")
        print("\nPentru debugging, verificați:")
        print("    1. Fișierul email este valid")
        print("    2. Sursele open source sunt disponibile")
        print("    3. Permisiunile de citire pentru fișier")

if __name__ == "__main__":
    main()