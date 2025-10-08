#!/usr/bin/env python3
"""
Advanced Reporting System for Email Tracking Detection

Features:
- JSON export for API integration
- Visual dashboard with threat trends
- Bulk analysis for multiple emails
- Statistical reporting and analytics
- Real-time threat intelligence stats
"""

import json
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any
import matplotlib.pyplot as plt
import seaborn as sns
from dataclasses import dataclass, asdict
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed

@dataclass
class ThreatReport:
    """Structured threat report for JSON export."""
    report_id: str
    timestamp: str
    email_path: str
    analysis_duration: float
    threat_summary: Dict[str, Any]
    tracking_pixels: List[Dict[str, Any]]
    css_threats: List[Dict[str, Any]]
    domain_analysis: Dict[str, Any]
    risk_assessment: Dict[str, Any]
    recommendations: List[str]
    metadata: Dict[str, Any]

@dataclass
class BulkAnalysisReport:
    """Comprehensive bulk analysis report."""
    batch_id: str
    timestamp: str
    total_emails: int
    processing_time: float
    summary_stats: Dict[str, Any]
    threat_trends: Dict[str, Any]
    top_threats: List[Dict[str, Any]]
    email_reports: List[ThreatReport]
    performance_metrics: Dict[str, Any]

class AdvancedReportingSystem:
    """Advanced reporting system with JSON export and analytics."""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Create subdirectories
        (self.output_dir / "json").mkdir(exist_ok=True)
        (self.output_dir / "dashboards").mkdir(exist_ok=True)
        (self.output_dir / "bulk_analysis").mkdir(exist_ok=True)
        (self.output_dir / "trends").mkdir(exist_ok=True)
        
        # Configure matplotlib for dashboard generation
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
    def generate_threat_report(self, analysis_result: Dict, email_path: str, 
                             analysis_duration: float) -> ThreatReport:
        """Generate structured threat report from analysis results."""
        
        report_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        
        # Extract tracking pixels with enhanced metadata
        tracking_pixels = []
        for pixel in analysis_result.get('pixels', []):
            enhanced_pixel = {
                'url': pixel.get('url', ''),
                'domain': pixel.get('domain', ''),
                'threat_level': pixel.get('threat_level', 'unknown'),
                'threat_score': pixel.get('threat_score', 0),
                'source': pixel.get('source', 'unknown'),
                'confidence': pixel.get('confidence', 'low'),
                'detection_method': pixel.get('detection_method', 'unknown'),
                'is_malicious': pixel.get('is_malicious', False),
                'categories': self._categorize_threat(pixel),
                'geolocation': self._get_domain_geolocation(pixel.get('domain', '')),
                'first_seen': timestamp  # In real system, this would be from DB
            }
            tracking_pixels.append(enhanced_pixel)
        
        # CSS threats analysis
        css_threats = []
        css_pixels = [p for p in analysis_result.get('pixels', []) 
                     if p.get('detection_method') == 'css_analysis']
        for css_pixel in css_pixels:
            css_threat = {
                'selector': css_pixel.get('css_selector', ''),
                'risk_level': css_pixel.get('threat_level', 'low'),
                'obfuscation_detected': self._detect_css_obfuscation(css_pixel),
                'steganography_risk': self._assess_steganography_risk(css_pixel)
            }
            css_threats.append(css_threat)
        
        # Domain analysis
        domains = list(set([p.get('domain', '') for p in tracking_pixels]))
        domain_analysis = {
            'unique_domains': len(domains),
            'high_risk_domains': len([d for d in domains if self._is_high_risk_domain(d)]),
            'domain_reputation': {domain: self._get_domain_reputation(domain) 
                                for domain in domains[:10]},  # Top 10
            'threat_distribution': self._analyze_threat_distribution(tracking_pixels)
        }
        
        # Risk assessment with detailed scoring
        risk_assessment = {
            'overall_risk': analysis_result.get('risk_assessment', 'unknown'),
            'threat_score': analysis_result.get('total_threat_score', 0),
            'risk_factors': self._identify_risk_factors(analysis_result),
            'confidence_level': self._calculate_confidence_level(tracking_pixels),
            'false_positive_probability': self._estimate_false_positive_rate(tracking_pixels)
        }
        
        # Generate recommendations
        recommendations = self._generate_recommendations(analysis_result, tracking_pixels)
        
        # Metadata
        metadata = {
            'analyzer_version': '2.0-optimized',
            'pattern_sources': ['MailTracker', 'GitHub', 'EasyPrivacy'],
            'total_patterns_used': analysis_result.get('patterns_used', 0),
            'cache_hit_rate': analysis_result.get('cache_hit_rate', 0),
            'processing_engine': 'optimized_o1_lookup'
        }
        
        return ThreatReport(
            report_id=report_id,
            timestamp=timestamp,
            email_path=email_path,
            analysis_duration=analysis_duration,
            threat_summary={
                'total_threats': len(tracking_pixels),
                'critical_threats': len([p for p in tracking_pixels if p['threat_level'] == 'critical']),
                'unique_domains': len(domains),
                'threat_categories': list(set([cat for p in tracking_pixels for cat in p['categories']]))
            },
            tracking_pixels=tracking_pixels,
            css_threats=css_threats,
            domain_analysis=domain_analysis,
            risk_assessment=risk_assessment,
            recommendations=recommendations,
            metadata=metadata
        )
    
    def export_json_report(self, report: ThreatReport, filename: Optional[str] = None) -> str:
        """Export threat report to JSON format for API integration."""
        
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"threat_report_{timestamp}_{report.report_id[:8]}.json"
        
        json_file = self.output_dir / "json" / filename
        
        # Convert to JSON-serializable format
        report_dict = asdict(report)
        
        # Add JSON schema information for validation
        report_dict['$schema'] = {
            'version': '1.0',
            'format': 'email_threat_analysis',
            'spec_url': 'https://github.com/pixel-tracker/threat-report-schema'
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)
        
        print(f"[+] 📄 JSON report exported: {json_file}")
        return str(json_file)
    
    def generate_visual_dashboard(self, reports: List[ThreatReport], 
                                title: str = "Email Threat Intelligence Dashboard") -> str:
        """Generate visual dashboard with threat trends and statistics."""
        
        if not reports:
            print("[-] No reports provided for dashboard generation")
            return ""
        
        # Create dashboard with multiple subplots
        fig, axes = plt.subplots(2, 3, figsize=(20, 12))
        fig.suptitle(title, fontsize=16, fontweight='bold')
        
        # 1. Threat Level Distribution
        threat_levels = []
        for report in reports:
            for pixel in report.tracking_pixels:
                threat_levels.append(pixel['threat_level'])
        
        threat_counts = pd.Series(threat_levels).value_counts()
        axes[0, 0].pie(threat_counts.values, labels=threat_counts.index, autopct='%1.1f%%')
        axes[0, 0].set_title('Threat Level Distribution')
        
        # 2. Top Malicious Domains
        domain_counts = {}
        for report in reports:
            for pixel in report.tracking_pixels:
                if pixel['is_malicious']:
                    domain = pixel['domain']
                    domain_counts[domain] = domain_counts.get(domain, 0) + 1
        
        if domain_counts:
            top_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            domains, counts = zip(*top_domains)
            axes[0, 1].barh(range(len(domains)), counts)
            axes[0, 1].set_yticks(range(len(domains)))
            axes[0, 1].set_yticklabels(domains)
            axes[0, 1].set_title('Top 10 Malicious Domains')
        
        # 3. Threat Score Timeline
        timestamps = [datetime.fromisoformat(r.timestamp.replace('Z', '+00:00')) for r in reports]
        threat_scores = [r.risk_assessment['threat_score'] for r in reports]
        axes[0, 2].plot(timestamps, threat_scores, marker='o')
        axes[0, 2].set_title('Threat Score Timeline')
        axes[0, 2].tick_params(axis='x', rotation=45)
        
        # 4. Detection Method Effectiveness
        detection_methods = []
        for report in reports:
            for pixel in report.tracking_pixels:
                detection_methods.append(pixel['detection_method'])
        
        method_counts = pd.Series(detection_methods).value_counts()
        axes[1, 0].bar(method_counts.index, method_counts.values)
        axes[1, 0].set_title('Detection Method Distribution')
        axes[1, 0].tick_params(axis='x', rotation=45)
        
        # 5. Threat Categories Heatmap
        categories_matrix = self._build_categories_matrix(reports)
        if len(categories_matrix) > 0:
            sns.heatmap(categories_matrix, ax=axes[1, 1], cmap='Reds', annot=True)
            axes[1, 1].set_title('Threat Categories Correlation')
        
        # 6. Performance Metrics
        analysis_times = [r.analysis_duration for r in reports]
        axes[1, 2].hist(analysis_times, bins=20, alpha=0.7)
        axes[1, 2].set_title('Analysis Duration Distribution')
        axes[1, 2].set_xlabel('Duration (seconds)')
        
        plt.tight_layout()
        
        # Save dashboard
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        dashboard_file = self.output_dir / "dashboards" / f"threat_dashboard_{timestamp}.png"
        plt.savefig(dashboard_file, dpi=300, bbox_inches='tight')
        plt.close()
        
        print(f"[+] 📊 Visual dashboard generated: {dashboard_file}")
        return str(dashboard_file)
    
    def bulk_analyze_emails(self, email_paths: List[str], 
                          detector) -> BulkAnalysisReport:
        """Perform bulk analysis of multiple emails with parallel processing."""
        
        batch_id = str(uuid.uuid4())
        start_time = time.time()
        timestamp = datetime.now(timezone.utc).isoformat()
        
        print(f"[+] 🚀 Starting bulk analysis of {len(email_paths)} emails...")
        print(f"[+] 📧 Batch ID: {batch_id}")
        
        # Parallel processing with progress tracking
        reports = []
        failed_analyses = []
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            # Submit all analysis tasks
            future_to_path = {
                executor.submit(self._analyze_single_email, detector, path): path 
                for path in email_paths
            }
            
            # Collect results
            completed = 0
            for future in as_completed(future_to_path):
                email_path = future_to_path[future]
                completed += 1
                
                try:
                    report = future.result()
                    if report:
                        reports.append(report)
                    print(f"    [{completed}/{len(email_paths)}] ✅ {email_path}")
                except Exception as e:
                    failed_analyses.append({'path': email_path, 'error': str(e)})
                    print(f"    [{completed}/{len(email_paths)}] ❌ {email_path}: {e}")
        
        processing_time = time.time() - start_time
        
        # Generate comprehensive statistics
        summary_stats = self._generate_bulk_summary_stats(reports)
        threat_trends = self._analyze_threat_trends(reports)
        top_threats = self._identify_top_threats(reports)
        performance_metrics = self._calculate_performance_metrics(reports, processing_time)
        
        bulk_report = BulkAnalysisReport(
            batch_id=batch_id,
            timestamp=timestamp,
            total_emails=len(email_paths),
            processing_time=processing_time,
            summary_stats=summary_stats,
            threat_trends=threat_trends,
            top_threats=top_threats,
            email_reports=reports,
            performance_metrics=performance_metrics
        )
        
        # Export bulk report
        self._export_bulk_report(bulk_report)
        
        # Generate bulk dashboard
        if reports:
            self.generate_visual_dashboard(
                reports, 
                f"Bulk Analysis Dashboard - {len(reports)} Emails"
            )
        
        print(f"[+] ✅ Bulk analysis complete!")
        print(f"[+] 📊 Processed: {len(reports)}/{len(email_paths)} emails")
        print(f"[+] ⏱️  Total time: {processing_time:.2f}s")
        print(f"[+] 🚀 Average: {processing_time/len(email_paths):.3f}s per email")
        
        return bulk_report
    
    def _analyze_single_email(self, detector, email_path: str) -> Optional[ThreatReport]:
        """Analyze single email and generate report."""
        try:
            start_time = time.time()
            result = detector.analyze_email_file(email_path)
            analysis_duration = time.time() - start_time
            
            if isinstance(result, dict):
                return self.generate_threat_report(result, email_path, analysis_duration)
            else:
                print(f"    [-] Invalid result format for {email_path}")
                return None
                
        except Exception as e:
            print(f"    [-] Analysis failed for {email_path}: {e}")
            return None
    
    def _categorize_threat(self, pixel: Dict) -> List[str]:
        """Categorize threat based on pixel characteristics."""
        categories = []
        
        url = pixel.get('url', '').lower()
        domain = pixel.get('domain', '').lower()
        
        if any(term in url for term in ['track', 'pixel', 'beacon']):
            categories.append('tracking')
        
        if any(term in url for term in ['analytics', 'stats', 'metrics']):
            categories.append('analytics')
        
        if any(term in url for term in ['campaign', 'utm_', 'email']):
            categories.append('email_tracking')
        
        if pixel.get('source') == 'MailTracker':
            categories.append('known_tracker')
        
        return categories or ['unknown']
    
    def _get_domain_geolocation(self, domain: str) -> Dict:
        """Get domain geolocation (placeholder - would use real geo API)."""
        # Simplified geolocation mapping
        geo_mapping = {
            'google.com': {'country': 'US', 'region': 'California'},
            'facebook.com': {'country': 'US', 'region': 'California'},
            'amazon.com': {'country': 'US', 'region': 'Washington'},
        }
        return geo_mapping.get(domain, {'country': 'Unknown', 'region': 'Unknown'})
    
    def _detect_css_obfuscation(self, css_pixel: Dict) -> bool:
        """Detect CSS obfuscation techniques."""
        # Simplified obfuscation detection
        css = css_pixel.get('css_content', '').lower()
        obfuscation_indicators = ['display:none', 'visibility:hidden', 'opacity:0']
        return any(indicator in css for indicator in obfuscation_indicators)
    
    def _assess_steganography_risk(self, css_pixel: Dict) -> str:
        """Assess steganography risk in CSS."""
        # Simplified steganography assessment
        return 'low'  # Would implement real steganography detection
    
    def _is_high_risk_domain(self, domain: str) -> bool:
        """Check if domain is high risk."""
        high_risk_indicators = [
            'track', 'pixel', 'analytics', 'beacon', 'collect',
            'doubleclick', 'googletagmanager', 'facebook'
        ]
        return any(indicator in domain.lower() for indicator in high_risk_indicators)
    
    def _get_domain_reputation(self, domain: str) -> Dict:
        """Get domain reputation score."""
        # Simplified reputation scoring
        if self._is_high_risk_domain(domain):
            return {'score': 25, 'category': 'tracking'}
        return {'score': 75, 'category': 'legitimate'}
    
    def _analyze_threat_distribution(self, pixels: List[Dict]) -> Dict:
        """Analyze threat distribution across different categories."""
        distribution = {}
        for pixel in pixels:
            for category in pixel.get('categories', []):
                distribution[category] = distribution.get(category, 0) + 1
        return distribution
    
    def _identify_risk_factors(self, analysis_result: Dict) -> List[str]:
        """Identify specific risk factors."""
        risk_factors = []
        
        if analysis_result.get('total_threat_score', 0) > 100:
            risk_factors.append('high_threat_score')
        
        if len(analysis_result.get('pixels', [])) > 5:
            risk_factors.append('multiple_trackers')
        
        return risk_factors
    
    def _calculate_confidence_level(self, pixels: List[Dict]) -> float:
        """Calculate overall confidence level."""
        if not pixels:
            return 0.0
        
        confidence_scores = {'high': 1.0, 'medium': 0.7, 'low': 0.3}
        total_confidence = sum(confidence_scores.get(p.get('confidence', 'low'), 0.3) 
                             for p in pixels)
        return total_confidence / len(pixels)
    
    def _estimate_false_positive_rate(self, pixels: List[Dict]) -> float:
        """Estimate false positive probability."""
        # Simplified FP estimation based on detection methods
        fp_rates = {
            'optimized_engine': 0.05,
            'fallback_regex': 0.15,
            'css_analysis': 0.10
        }
        
        if not pixels:
            return 0.0
        
        avg_fp_rate = sum(fp_rates.get(p.get('detection_method', 'fallback_regex'), 0.15) 
                         for p in pixels) / len(pixels)
        return avg_fp_rate
    
    def _generate_recommendations(self, analysis_result: Dict, pixels: List[Dict]) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if analysis_result.get('risk_assessment') == 'critical':
            recommendations.append("🚨 CRITICAL: Do not interact with this email")
            recommendations.append("🛡️ Block sender and report as phishing")
        
        if len(pixels) > 3:
            recommendations.append("📧 Multiple trackers detected - consider email filtering")
        
        unique_domains = len(set(p.get('domain', '') for p in pixels))
        if unique_domains > 2:
            recommendations.append("🌐 Multiple tracking domains - high privacy risk")
        
        return recommendations or ["✅ Email appears safe for interaction"]
    
    def _build_categories_matrix(self, reports: List[ThreatReport]) -> pd.DataFrame:
        """Build categories correlation matrix for heatmap."""
        # Simplified correlation matrix
        categories = ['tracking', 'analytics', 'email_tracking', 'known_tracker']
        matrix_data = []
        
        for cat1 in categories:
            row = []
            for cat2 in categories:
                # Count co-occurrences
                cooccurrence = 0
                for report in reports:
                    for pixel in report.tracking_pixels:
                        pixel_cats = pixel.get('categories', [])
                        if cat1 in pixel_cats and cat2 in pixel_cats:
                            cooccurrence += 1
                row.append(cooccurrence)
            matrix_data.append(row)
        
        return pd.DataFrame(matrix_data, index=categories, columns=categories)
    
    def _generate_bulk_summary_stats(self, reports: List[ThreatReport]) -> Dict:
        """Generate summary statistics for bulk analysis."""
        if not reports:
            return {}
        
        total_threats = sum(len(r.tracking_pixels) for r in reports)
        critical_threats = sum(
            len([p for p in r.tracking_pixels if p['threat_level'] == 'critical']) 
            for r in reports
        )
        
        return {
            'total_threats_detected': total_threats,
            'critical_threats': critical_threats,
            'emails_with_threats': len([r for r in reports if r.tracking_pixels]),
            'clean_emails': len([r for r in reports if not r.tracking_pixels]),
            'average_threats_per_email': total_threats / len(reports),
            'threat_detection_rate': len([r for r in reports if r.tracking_pixels]) / len(reports)
        }
    
    def _analyze_threat_trends(self, reports: List[ThreatReport]) -> Dict:
        """Analyze threat trends across the batch."""
        domain_frequency = {}
        source_distribution = {}
        
        for report in reports:
            for pixel in report.tracking_pixels:
                domain = pixel.get('domain', 'unknown')
                source = pixel.get('source', 'unknown')
                
                domain_frequency[domain] = domain_frequency.get(domain, 0) + 1
                source_distribution[source] = source_distribution.get(source, 0) + 1
        
        return {
            'most_common_domains': sorted(domain_frequency.items(), 
                                        key=lambda x: x[1], reverse=True)[:10],
            'source_distribution': source_distribution,
            'emerging_threats': self._identify_emerging_threats(reports)
        }
    
    def _identify_top_threats(self, reports: List[ThreatReport]) -> List[Dict]:
        """Identify top threats across all analyzed emails."""
        all_pixels = []
        for report in reports:
            for pixel in report.tracking_pixels:
                pixel['report_id'] = report.report_id
                all_pixels.append(pixel)
        
        # Sort by threat score
        top_threats = sorted(all_pixels, key=lambda x: x.get('threat_score', 0), reverse=True)[:20]
        
        return top_threats
    
    def _identify_emerging_threats(self, reports: List[ThreatReport]) -> List[Dict]:
        """Identify emerging threat patterns."""
        # Simplified emerging threats identification
        new_domains = set()
        for report in reports:
            for pixel in report.tracking_pixels:
                if pixel.get('source') == 'GitHub':  # New patterns from GitHub
                    new_domains.add(pixel.get('domain', ''))
        
        return [{'domain': domain, 'status': 'emerging'} for domain in list(new_domains)[:5]]
    
    def _calculate_performance_metrics(self, reports: List[ThreatReport], 
                                     total_time: float) -> Dict:
        """Calculate performance metrics for bulk analysis."""
        if not reports:
            return {}
        
        analysis_times = [r.analysis_duration for r in reports]
        
        return {
            'total_processing_time': total_time,
            'average_analysis_time': sum(analysis_times) / len(analysis_times),
            'fastest_analysis': min(analysis_times),
            'slowest_analysis': max(analysis_times),
            'emails_per_second': len(reports) / total_time,
            'parallel_efficiency': len(reports) / (total_time / min(analysis_times))
        }
    
    def _export_bulk_report(self, bulk_report: BulkAnalysisReport):
        """Export bulk analysis report to JSON."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"bulk_analysis_{timestamp}_{bulk_report.batch_id[:8]}.json"
        
        json_file = self.output_dir / "bulk_analysis" / filename
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(asdict(bulk_report), f, indent=2, ensure_ascii=False)
        
        print(f"[+] 📊 Bulk analysis report exported: {json_file}")


def main():
    """Demo of advanced reporting system."""
    import sys
    sys.path.append('.')
    from scripts.final_pixel_detector import FinalPixelDetector
    
    print("🚀 Advanced Reporting System Demo")
    print("=" * 50)
    
    # Initialize systems
    reporting = AdvancedReportingSystem()
    detector = FinalPixelDetector()
    detector.initialize()
    
    # Test with sample emails
    test_emails = [
        "test_emails/real_trackers.eml",
        "test_emails/spyware_malware.eml", 
        "test_emails/html_tracking.eml"
    ]
    
    # Filter existing emails
    existing_emails = [email for email in test_emails if Path(email).exists()]
    
    if existing_emails:
        print(f"📧 Found {len(existing_emails)} test emails")
        
        # Bulk analysis
        bulk_report = reporting.bulk_analyze_emails(existing_emails, detector)
        
        print(f"\n📊 Bulk Analysis Results:")
        print(f"  Total threats: {bulk_report.summary_stats.get('total_threats_detected', 0)}")
        print(f"  Processing time: {bulk_report.processing_time:.2f}s")
    else:
        print("❌ No test emails found")


if __name__ == "__main__":
    main()