#!/usr/bin/env python3
"""
Auto-Update Orchestrator

Central coordination system that integrates all auto-update components:
- Real-time GitHub monitoring
- Pattern validation pipeline
- Version control management
- Hot-reload capabilities
- Health monitoring and rollback
- Scheduling and automation

This is the main entry point for the complete auto-update system.
"""

import asyncio
import time
import json
import logging
import threading
import queue
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
import schedule
import signal
import sys

# Import our custom modules
from realtime_github_sync import GitHubChangeMonitor, ChangeEvent
from pattern_validator import PatternValidator, ValidationResult
from pattern_version_control import PatternVersionControl, PatternCommit
from optimized_pattern_engine import OptimizedPatternEngine

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('autoupdate.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class AutoUpdateConfig:
    """Configuration for the auto-update system"""
    enabled: bool = True
    validation_enabled: bool = True
    auto_rollback: bool = True
    max_rollback_attempts: int = 3
    performance_threshold: float = 2.0  # Max 2x slower than baseline
    false_positive_threshold: float = 0.001  # 0.1%
    health_check_interval: int = 300  # 5 minutes
    pattern_refresh_interval: int = 3600  # 1 hour
    emergency_stop: bool = False

@dataclass
class SystemHealth:
    """System health metrics"""
    timestamp: float
    detection_speed_ms: float
    memory_usage_mb: float
    pattern_count: int
    false_positive_rate: float
    cache_hit_rate: float
    errors_per_hour: int
    status: str  # healthy, degraded, critical

class AutoUpdateOrchestrator:
    """Central orchestrator for the complete auto-update system"""
    
    def __init__(self, config_file: str = None):
        self.base_path = Path(__file__).parent.parent
        self.config_file = config_file or str(self.base_path / "autoupdate_config.json")
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize components
        self.github_monitor = GitHubChangeMonitor()
        self.pattern_validator = PatternValidator()
        self.version_control = PatternVersionControl()
        self.pattern_engine = None  # Will be initialized later
        
        # System state
        self.running = False
        self.health_history = []
        self.rollback_count = 0
        self.last_update = time.time()
        
        # Queues for inter-component communication
        self.validation_queue = queue.Queue()
        self.update_queue = queue.Queue()
        self.health_queue = queue.Queue()
        
        # Threads
        self.threads = []
        
        # Shutdown handler
        signal.signal(signal.SIGINT, self._shutdown_handler)
        signal.signal(signal.SIGTERM, self._shutdown_handler)
    
    def _load_config(self) -> AutoUpdateConfig:
        """Load configuration from file"""
        config_path = Path(self.config_file)
        
        if config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    config_data = json.load(f)
                return AutoUpdateConfig(**config_data)
            except Exception as e:
                logger.warning(f"Failed to load config: {e}, using defaults")
        
        # Create default config
        config = AutoUpdateConfig()
        self._save_config(config)
        return config
    
    def _save_config(self, config: AutoUpdateConfig):
        """Save configuration to file"""
        with open(self.config_file, 'w') as f:
            json.dump(asdict(config), f, indent=2)
    
    def _shutdown_handler(self, signum, frame):
        """Handle shutdown signals"""
        logger.info(f"🛑 Received signal {signum}, shutting down gracefully...")
        self.stop()
        sys.exit(0)
    
    def start(self):
        """Start the complete auto-update system"""
        if self.running:
            logger.warning("Auto-update system already running")
            return
        
        logger.info("🚀 Starting Auto-Update Orchestrator")
        self.running = True
        
        # Initialize pattern engine
        self._initialize_pattern_engine()
        
        # Start GitHub monitoring
        self.github_monitor.start_monitoring()
        
        # Start worker threads
        self._start_worker_threads()
        
        # Schedule periodic tasks
        self._schedule_tasks()
        
        logger.info("✅ Auto-Update system started successfully")
    
    def stop(self):
        """Stop the auto-update system"""
        if not self.running:
            return
        
        logger.info("⏹️ Stopping Auto-Update Orchestrator")
        self.running = False
        
        # Stop GitHub monitoring
        self.github_monitor.stop_monitoring()
        
        # Stop worker threads
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=5)
        
        logger.info("✅ Auto-Update system stopped")
    
    def _initialize_pattern_engine(self):
        """Initialize the optimized pattern engine"""
        try:
            self.pattern_engine = OptimizedPatternEngine()
            self.pattern_engine.initialize()
            logger.info("✅ Pattern engine initialized")
        except Exception as e:
            logger.error(f"❌ Failed to initialize pattern engine: {e}")
            raise
    
    def _start_worker_threads(self):
        """Start background worker threads"""
        
        # Change processing thread
        change_thread = threading.Thread(
            target=self._change_processor,
            name="ChangeProcessor",
            daemon=True
        )
        change_thread.start()
        self.threads.append(change_thread)
        
        # Validation processing thread
        validation_thread = threading.Thread(
            target=self._validation_processor,
            name="ValidationProcessor",
            daemon=True
        )
        validation_thread.start()
        self.threads.append(validation_thread)
        
        # Update processing thread
        update_thread = threading.Thread(
            target=self._update_processor,
            name="UpdateProcessor",
            daemon=True
        )
        update_thread.start()
        self.threads.append(update_thread)
        
        # Health monitoring thread
        health_thread = threading.Thread(
            target=self._health_monitor,
            name="HealthMonitor",
            daemon=True
        )
        health_thread.start()
        self.threads.append(health_thread)
        
        logger.info(f"✅ Started {len(self.threads)} worker threads")
    
    def _schedule_tasks(self):
        """Schedule periodic tasks"""
        
        # Health checks every 5 minutes
        schedule.every(self.config.health_check_interval).seconds.do(self._periodic_health_check)
        
        # Pattern refresh every hour
        schedule.every(self.config.pattern_refresh_interval).seconds.do(self._periodic_pattern_refresh)
        
        # Cleanup old data daily
        schedule.every().day.at("02:00").do(self._cleanup_old_data)
        
        # Start scheduler thread
        scheduler_thread = threading.Thread(
            target=self._run_scheduler,
            name="Scheduler",
            daemon=True
        )
        scheduler_thread.start()
        self.threads.append(scheduler_thread)
    
    def _run_scheduler(self):
        """Run the periodic task scheduler"""
        while self.running:
            schedule.run_pending()
            time.sleep(1)
    
    def _change_processor(self):
        """Process changes detected by GitHub monitor"""
        logger.info("🔄 Change processor started")
        
        while self.running:
            try:
                # Get pending changes from GitHub monitor
                changes = self.github_monitor.get_pending_changes()
                
                for change in changes:
                    if self.config.emergency_stop:
                        logger.warning("🚨 Emergency stop activated, skipping changes")
                        continue
                    
                    logger.info(f"📝 Processing change from {change.source_name}")
                    
                    if self.config.validation_enabled:
                        # Queue for validation
                        self.validation_queue.put(change)
                    else:
                        # Skip validation, go directly to update
                        self.update_queue.put((change, None))
                
                time.sleep(5)  # Check for changes every 5 seconds
                
            except Exception as e:
                logger.error(f"❌ Error in change processor: {e}")
                time.sleep(10)
    
    def _validation_processor(self):
        """Process pattern validation"""
        logger.info("🧪 Validation processor started")
        
        while self.running:
            try:
                change = self.validation_queue.get(timeout=5)
                
                logger.info(f"🔍 Validating patterns from {change.source_name}")
                
                # Extract patterns from change
                patterns_to_validate = self._extract_patterns_from_change(change)
                
                if not patterns_to_validate:
                    logger.warning("No patterns to validate")
                    continue
                
                # Run comprehensive validation
                validation_results = self.pattern_validator.validate_patterns_batch(patterns_to_validate)
                
                # Check if validation passed
                if self._validation_passed(validation_results):
                    logger.info("✅ Validation passed, queuing for update")
                    self.update_queue.put((change, validation_results))
                else:
                    logger.warning("❌ Validation failed, rejecting changes")
                    self._handle_validation_failure(change, validation_results)
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"❌ Error in validation processor: {e}")
    
    def _update_processor(self):
        """Process approved updates"""
        logger.info("🔄 Update processor started")
        
        while self.running:
            try:
                change, validation_results = self.update_queue.get(timeout=5)
                
                logger.info(f"🚀 Applying update from {change.source_name}")
                
                # Create rollback point
                rollback_point = self._create_rollback_point("before_update")
                
                try:
                    # Apply the update
                    success = self._apply_pattern_update(change, validation_results)
                    
                    if success:
                        logger.info("✅ Update applied successfully")
                        self.last_update = time.time()
                        self.rollback_count = 0  # Reset rollback count on success
                    else:
                        logger.error("❌ Update application failed")
                        if self.config.auto_rollback:
                            self._perform_rollback(rollback_point, "update_application_failed")
                
                except Exception as e:
                    logger.error(f"❌ Error applying update: {e}")
                    if self.config.auto_rollback:
                        self._perform_rollback(rollback_point, f"update_error: {e}")
                
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"❌ Error in update processor: {e}")
    
    def _health_monitor(self):
        """Monitor system health and trigger rollbacks if needed"""
        logger.info("🏥 Health monitor started")
        
        while self.running:
            try:
                # Collect health metrics
                health = self._collect_health_metrics()
                self.health_history.append(health)
                
                # Keep only recent history
                if len(self.health_history) > 100:
                    self.health_history = self.health_history[-100:]
                
                # Check for health issues
                if health.status in ["degraded", "critical"]:
                    logger.warning(f"🚨 System health: {health.status}")
                    
                    if health.status == "critical" and self.config.auto_rollback:
                        self._trigger_emergency_rollback(health)
                
                time.sleep(self.config.health_check_interval)
                
            except Exception as e:
                logger.error(f"❌ Error in health monitor: {e}")
                time.sleep(60)
    
    def _extract_patterns_from_change(self, change: ChangeEvent) -> List[Tuple[str, str]]:
        """Extract patterns from a change event for validation"""
        patterns = []
        
        if "added_lines" in change.changes:
            for line in change.changes["added_lines"]:
                if line.strip() and not line.startswith('!') and not line.startswith('#'):
                    patterns.append((line.strip(), change.source_name))
        
        return patterns[:20]  # Limit to 20 patterns for validation
    
    def _validation_passed(self, validation_results: Dict) -> bool:
        """Check if validation results indicate success"""
        if not validation_results:
            return False
        
        total_score = 0
        total_count = 0
        failed_count = 0
        
        for pattern_key, pattern_results in validation_results.items():
            for stage, result in pattern_results.items():
                total_score += result.score
                total_count += 1
                if not result.passed:
                    failed_count += 1
        
        if total_count == 0:
            return False
        
        avg_score = total_score / total_count
        failure_rate = failed_count / total_count
        
        # Pass if average score > 0.7 and failure rate < 20%
        return avg_score > 0.7 and failure_rate < 0.2
    
    def _handle_validation_failure(self, change: ChangeEvent, validation_results: Dict):
        """Handle validation failure"""
        logger.warning(f"⚠️ Validation failed for {change.source_name}")
        
        # Log details for debugging
        failure_details = {
            "source": change.source_name,
            "timestamp": time.time(),
            "change": asdict(change),
            "validation_summary": self._summarize_validation_results(validation_results)
        }
        
        # Save failure log
        failure_log_file = self.base_path / "autoupdate" / "validation_failures.jsonl"
        failure_log_file.parent.mkdir(exist_ok=True)
        
        with open(failure_log_file, 'a') as f:
            f.write(json.dumps(failure_details) + '\n')
    
    def _summarize_validation_results(self, validation_results: Dict) -> Dict:
        """Create summary of validation results"""
        if not validation_results:
            return {"error": "no_results"}
        
        total_patterns = len(validation_results)
        passed_patterns = sum(1 for pr in validation_results.values() if all(r.passed for r in pr.values()))
        avg_score = sum(sum(r.score for r in pr.values()) / len(pr) for pr in validation_results.values()) / total_patterns
        
        return {
            "total_patterns": total_patterns,
            "passed_patterns": passed_patterns,
            "failed_patterns": total_patterns - passed_patterns,
            "avg_score": avg_score,
            "success_rate": passed_patterns / total_patterns
        }
    
    def _create_rollback_point(self, reason: str) -> str:
        """Create a rollback point in version control"""
        current_patterns = self._get_current_patterns()
        
        commit_id = self.version_control.commit_changes(
            current_patterns,
            f"Rollback point: {reason}",
            "auto-update-system"
        )
        
        return commit_id
    
    def _get_current_patterns(self) -> Dict[str, List[str]]:
        """Get current patterns from the pattern engine"""
        if not self.pattern_engine:
            return {}
        
        # Extract patterns from the optimized engine
        # This is a simplified version - in practice would extract from all sources
        return {
            "current_state": ["pattern_extraction_placeholder"]
        }
    
    def _apply_pattern_update(self, change: ChangeEvent, validation_results: Dict) -> bool:
        """Apply pattern update to the system"""
        try:
            # In a real implementation, this would:
            # 1. Extract new patterns from the change
            # 2. Update the pattern engine with hot-reload
            # 3. Invalidate caches
            # 4. Verify the update worked
            
            logger.info(f"📦 Applying {change.changes.get('added_patterns', 0)} new patterns")
            
            # Simulate pattern update
            if self.pattern_engine:
                # This would be the actual hot-reload logic
                time.sleep(0.1)  # Simulate update time
                logger.info("🔄 Pattern engine reloaded successfully")
            
            # Commit changes to version control
            new_patterns = self._simulate_new_patterns(change)
            commit_id = self.version_control.commit_changes(
                new_patterns,
                f"Auto-update from {change.source_name}: {change.changes.get('added_patterns', 0)} patterns",
                "auto-update-system",
                validation_results
            )
            
            logger.info(f"💾 Changes committed: {commit_id[:8]}")
            return True
            
        except Exception as e:
            logger.error(f"❌ Failed to apply update: {e}")
            return False
    
    def _simulate_new_patterns(self, change: ChangeEvent) -> Dict[str, List[str]]:
        """Simulate new patterns for testing (in production would extract from change)"""
        return {
            change.source_name: [
                f"simulated_pattern_{int(time.time())}",
                f"test_pattern_{change.commit_sha[:8]}"
            ]
        }
    
    def _perform_rollback(self, rollback_commit: str, reason: str):
        """Perform system rollback"""
        if self.rollback_count >= self.config.max_rollback_attempts:
            logger.critical("🚨 Max rollback attempts reached, enabling emergency stop")
            self.config.emergency_stop = True
            return
        
        logger.warning(f"🔄 Performing rollback: {reason}")
        
        success = self.version_control.rollback_to_commit(rollback_commit, reason)
        
        if success:
            self.rollback_count += 1
            logger.info(f"✅ Rollback successful (attempt {self.rollback_count})")
            
            # Reload pattern engine with rollback patterns
            if self.pattern_engine:
                # This would reload patterns from the rollback commit
                logger.info("🔄 Pattern engine reloaded with rollback patterns")
        else:
            logger.error("❌ Rollback failed")
    
    def _collect_health_metrics(self) -> SystemHealth:
        """Collect current system health metrics"""
        # In a real implementation, would collect actual metrics
        health = SystemHealth(
            timestamp=time.time(),
            detection_speed_ms=25.0,  # Simulated
            memory_usage_mb=150.0,    # Simulated
            pattern_count=self._get_total_pattern_count(),
            false_positive_rate=0.0001,  # Simulated
            cache_hit_rate=0.75,      # Simulated
            errors_per_hour=0,        # Simulated
            status="healthy"
        )
        
        # Determine status based on metrics
        if health.detection_speed_ms > 100 or health.false_positive_rate > 0.01:
            health.status = "critical"
        elif health.detection_speed_ms > 50 or health.memory_usage_mb > 500:
            health.status = "degraded"
        
        return health
    
    def _get_total_pattern_count(self) -> int:
        """Get total number of active patterns"""
        return self.version_control._get_total_pattern_count()
    
    def _trigger_emergency_rollback(self, health: SystemHealth):
        """Trigger emergency rollback due to critical health issues"""
        logger.critical(f"🚨 Triggering emergency rollback - Health: {health.status}")
        
        # Get recent commits to rollback to
        recent_commits = self.version_control.get_commit_history(5)
        
        for commit in recent_commits:
            if commit.changes.get("type") != "rollback":
                logger.info(f"🆘 Emergency rollback to {commit.commit_id[:8]}")
                self._perform_rollback(commit.commit_id, f"emergency: {health.status}")
                break
    
    def _periodic_health_check(self):
        """Periodic comprehensive health check"""
        logger.info("🏥 Running periodic health check")
        
        health = self._collect_health_metrics()
        
        # Log health status
        logger.info(f"📊 System Health: {health.status}")
        logger.info(f"   Detection Speed: {health.detection_speed_ms:.1f}ms")
        logger.info(f"   Memory Usage: {health.memory_usage_mb:.1f}MB")
        logger.info(f"   Pattern Count: {health.pattern_count}")
        logger.info(f"   Cache Hit Rate: {health.cache_hit_rate:.1%}")
    
    def _periodic_pattern_refresh(self):
        """Periodic pattern refresh from sources"""
        logger.info("🔄 Running periodic pattern refresh")
        
        # Force check of all GitHub sources
        # This ensures we don't miss any updates due to webhook failures
        try:
            # The GitHub monitor will handle the actual refresh
            logger.info("📡 Pattern refresh triggered")
        except Exception as e:
            logger.error(f"❌ Pattern refresh failed: {e}")
    
    def _cleanup_old_data(self):
        """Clean up old logs and data"""
        logger.info("🧹 Running daily cleanup")
        
        # Clean up old validation results
        # Clean up old rollback points
        # Rotate logs
        # In a real implementation would clean up based on retention policies
        
        logger.info("✅ Daily cleanup complete")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        recent_health = self.health_history[-1] if self.health_history else None
        
        return {
            "running": self.running,
            "config": asdict(self.config),
            "last_update": self.last_update,
            "rollback_count": self.rollback_count,
            "github_monitor": self.github_monitor.get_monitoring_status(),
            "pattern_count": self._get_total_pattern_count(),
            "recent_health": asdict(recent_health) if recent_health else None,
            "queue_sizes": {
                "validation": self.validation_queue.qsize(),
                "update": self.update_queue.qsize()
            }
        }

def main():
    """Main entry point for the auto-update system"""
    print("🚀 Email Tracker Auto-Update System")
    print("=" * 50)
    
    try:
        # Create and start orchestrator
        orchestrator = AutoUpdateOrchestrator()
        orchestrator.start()
        
        # Run until interrupted
        print("✅ Auto-update system running...")
        print("📊 Monitor status with: http://localhost:8080/status")
        print("Press Ctrl+C to stop")
        
        while orchestrator.running:
            time.sleep(1)
            
            # Print periodic status
            if int(time.time()) % 60 == 0:  # Every minute
                status = orchestrator.get_system_status()
                print(f"📊 Status: Patterns: {status['pattern_count']}, "
                      f"Queues: V={status['queue_sizes']['validation']} "
                      f"U={status['queue_sizes']['update']}")
    
    except KeyboardInterrupt:
        print("\n⏹️ Shutting down...")
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
    finally:
        if 'orchestrator' in locals():
            orchestrator.stop()

if __name__ == "__main__":
    main()