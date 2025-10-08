#!/usr/bin/env python3
"""
Email Threat Analysis CLI Tool with Advanced Reporting

Command-line interface for email threat analysis with:
- JSON export for API integration
- Visual dashboard generation  
- Bulk processing capabilities
- Real-time threat intelligence
"""

import argparse
import sys
import time
from pathlib import Path
sys.path.append('.')

from scripts.final_pixel_detector import FinalPixelDetector
from scripts.advanced_reporting import AdvancedReportingSystem

def analyze_single_email(email_path: str, export_json: bool = False, 
                        generate_dashboard: bool = False):
    """Analyze single email with optional reporting."""
    print(f"🔍 Analyzing: {email_path}")
    
    # Initialize detector
    detector = FinalPixelDetector()
    detector.initialize()
    
    # Initialize reporting
    reporting = AdvancedReportingSystem()
    
    # Analyze email
    start_time = time.time()
    result = detector.analyze_email_file(email_path)
    analysis_duration = time.time() - start_time
    
    # Generate threat report
    threat_report = reporting.generate_threat_report(result, email_path, analysis_duration)
    
    # Print summary
    print(f"\n📊 Analysis Results:")
    print(f"  Total threats: {len(threat_report.tracking_pixels)}")
    print(f"  Risk level: {threat_report.risk_assessment['overall_risk']}")
    print(f"  Analysis time: {analysis_duration:.3f}s")
    
    # Export JSON if requested
    if export_json:
        json_file = reporting.export_json_report(threat_report)
        print(f"  JSON exported: {json_file}")
    
    # Generate dashboard if requested
    if generate_dashboard:
        dashboard_file = reporting.generate_visual_dashboard([threat_report])
        print(f"  Dashboard: {dashboard_file}")
    
    return threat_report

def bulk_analyze_emails(email_paths: list, export_json: bool = False,
                       generate_dashboard: bool = False):
    """Bulk analyze multiple emails."""
    print(f"🚀 Bulk analyzing {len(email_paths)} emails...")
    
    # Initialize systems
    detector = FinalPixelDetector()
    detector.initialize()
    
    reporting = AdvancedReportingSystem()
    
    # Bulk analysis
    bulk_report = reporting.bulk_analyze_emails(email_paths, detector)
    
    # Print summary
    print(f"\n📊 Bulk Analysis Summary:")
    print(f"  Emails processed: {bulk_report.total_emails}")
    print(f"  Total threats: {bulk_report.summary_stats['total_threats_detected']}")
    print(f"  Clean emails: {bulk_report.summary_stats['clean_emails']}")
    print(f"  Processing time: {bulk_report.processing_time:.2f}s")
    print(f"  Average per email: {bulk_report.processing_time/bulk_report.total_emails:.3f}s")
    
    return bulk_report

def main():
    """Main CLI interface."""
    parser = argparse.ArgumentParser(
        description="Advanced Email Threat Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze single email with JSON export
  py cli_analyzer.py -e email.eml --json
  
  # Bulk analyze with dashboard
  py cli_analyzer.py -b test_emails/*.eml --dashboard
  
  # Full analysis with all exports
  py cli_analyzer.py -e email.eml --json --dashboard
        """
    )
    
    # Email input options
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--email', type=str, 
                      help='Single email file to analyze')
    group.add_argument('-b', '--bulk', nargs='+', 
                      help='Multiple email files for bulk analysis')
    
    # Export options
    parser.add_argument('--json', action='store_true',
                       help='Export results to JSON format')
    parser.add_argument('--dashboard', action='store_true',
                       help='Generate visual dashboard')
    parser.add_argument('--output-dir', type=str, default='reports',
                       help='Output directory for reports')
    
    # Performance options
    parser.add_argument('--threads', type=int, default=4,
                       help='Number of threads for parallel processing')
    
    args = parser.parse_args()
    
    print("🛡️ Advanced Email Threat Analysis Tool")
    print("=" * 50)
    
    try:
        if args.email:
            # Single email analysis
            email_path = Path(args.email)
            if not email_path.exists():
                print(f"❌ Email file not found: {args.email}")
                sys.exit(1)
            
            analyze_single_email(str(email_path), args.json, args.dashboard)
            
        elif args.bulk:
            # Bulk analysis
            email_paths = []
            for path_pattern in args.bulk:
                path = Path(path_pattern)
                if path.is_file():
                    email_paths.append(str(path))
                else:
                    # Handle glob patterns
                    parent = path.parent
                    pattern = path.name
                    matches = list(parent.glob(pattern))
                    email_paths.extend([str(m) for m in matches if m.is_file()])
            
            if not email_paths:
                print("❌ No email files found")
                sys.exit(1)
            
            bulk_analyze_emails(email_paths, args.json, args.dashboard)
    
    except KeyboardInterrupt:
        print("\n⚠️ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()