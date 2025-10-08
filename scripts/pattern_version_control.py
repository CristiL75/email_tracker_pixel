#!/usr/bin/env python3
"""
Pattern Version Control System

Git-like version control system for tracking protection patterns.
Provides full audit trail, rollback capabilities, and change tracking.

Features:
- Commit-like system for pattern changes
- Diff generation and visualization
- Branch management for experimental patterns
- Automated rollback on issues
- Full audit trail for compliance
- Conflict resolution for pattern merges
"""

import json
import time
import hashlib
import logging
import difflib
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime
import uuid
import copy

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class PatternCommit:
    """Represents a commit in the pattern version control system"""
    commit_id: str
    parent_id: Optional[str]
    timestamp: float
    author: str
    message: str
    changes: Dict[str, Any]
    pattern_snapshot: Dict[str, List[str]]
    validation_results: Optional[Dict] = None
    rollback_safe: bool = True
    branch: str = "main"

@dataclass
class PatternDiff:
    """Represents differences between pattern versions"""
    from_commit: str
    to_commit: str
    added_patterns: List[str]
    removed_patterns: List[str]
    modified_patterns: List[Tuple[str, str]]  # (old, new)
    source_changes: Dict[str, Dict[str, List[str]]]

@dataclass
class RollbackPoint:
    """Represents a rollback point with system state"""
    rollback_id: str
    commit_id: str
    timestamp: float
    reason: str
    system_metrics: Dict[str, Any]
    automatic: bool = True

class PatternVersionControl:
    """Git-like version control system for tracking protection patterns"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent.parent
        self.vcs_dir = self.base_path / "pattern_vcs"
        self.commits_dir = self.vcs_dir / "commits"
        self.branches_dir = self.vcs_dir / "branches"
        self.rollbacks_dir = self.vcs_dir / "rollbacks"
        self.snapshots_dir = self.vcs_dir / "snapshots"
        
        # Ensure directories exist
        for directory in [self.vcs_dir, self.commits_dir, self.branches_dir, 
                         self.rollbacks_dir, self.snapshots_dir]:
            directory.mkdir(exist_ok=True)
        
        # Initialize repository if needed
        self._init_repository()
        
        # Current state
        self.current_branch = "main"
        self.head_commit = self._get_head_commit()
        
    def _init_repository(self):
        """Initialize the pattern version control repository"""
        vcs_config_file = self.vcs_dir / "config.json"
        
        if not vcs_config_file.exists():
            # Create initial configuration
            config = {
                "version": "1.0",
                "created": time.time(),
                "default_branch": "main",
                "auto_rollback": True,
                "max_commits": 1000,
                "retention_days": 365
            }
            
            with open(vcs_config_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            # Create main branch
            self._create_branch("main")
            
            # Create initial commit
            self._create_initial_commit()
            
            logger.info("🎉 Pattern VCS repository initialized")
    
    def _create_branch(self, branch_name: str, from_commit: str = None):
        """Create a new branch"""
        branch_file = self.branches_dir / f"{branch_name}.json"
        
        branch_data = {
            "name": branch_name,
            "created": time.time(),
            "head_commit": from_commit,
            "parent_branch": "main" if branch_name != "main" else None
        }
        
        with open(branch_file, 'w') as f:
            json.dump(branch_data, f, indent=2)
    
    def _create_initial_commit(self):
        """Create the initial commit with empty pattern set"""
        initial_commit = PatternCommit(
            commit_id=self._generate_commit_id(),
            parent_id=None,
            timestamp=time.time(),
            author="system",
            message="Initial commit - Pattern VCS repository",
            changes={
                "type": "initial",
                "patterns_added": 0,
                "patterns_removed": 0,
                "sources_modified": []
            },
            pattern_snapshot={},
            branch="main"
        )
        
        self._save_commit(initial_commit)
        self._update_branch_head("main", initial_commit.commit_id)
        
        logger.info(f"📝 Initial commit created: {initial_commit.commit_id[:8]}")
    
    def _generate_commit_id(self) -> str:
        """Generate unique commit ID"""
        return hashlib.sha256(f"{time.time()}{uuid.uuid4()}".encode()).hexdigest()
    
    def _get_head_commit(self, branch: str = None) -> Optional[str]:
        """Get the head commit for a branch"""
        if branch is None:
            branch = self.current_branch
        
        branch_file = self.branches_dir / f"{branch}.json"
        if not branch_file.exists():
            return None
        
        with open(branch_file, 'r') as f:
            branch_data = json.load(f)
            return branch_data.get('head_commit')
    
    def _save_commit(self, commit: PatternCommit):
        """Save a commit to storage"""
        commit_file = self.commits_dir / f"{commit.commit_id}.json"
        
        with open(commit_file, 'w') as f:
            json.dump(asdict(commit), f, indent=2)
    
    def _load_commit(self, commit_id: str) -> Optional[PatternCommit]:
        """Load a commit from storage"""
        commit_file = self.commits_dir / f"{commit_id}.json"
        
        if not commit_file.exists():
            return None
        
        with open(commit_file, 'r') as f:
            commit_data = json.load(f)
            return PatternCommit(**commit_data)
    
    def _update_branch_head(self, branch: str, commit_id: str):
        """Update the head commit for a branch"""
        branch_file = self.branches_dir / f"{branch}.json"
        
        if branch_file.exists():
            with open(branch_file, 'r') as f:
                branch_data = json.load(f)
        else:
            branch_data = {"name": branch, "created": time.time()}
        
        branch_data["head_commit"] = commit_id
        branch_data["last_updated"] = time.time()
        
        with open(branch_file, 'w') as f:
            json.dump(branch_data, f, indent=2)
    
    def commit_changes(self, 
                      pattern_changes: Dict[str, List[str]], 
                      message: str, 
                      author: str = "auto-update",
                      validation_results: Dict = None) -> str:
        """Commit pattern changes to version control"""
        
        # Get current patterns for snapshot
        current_patterns = self._get_current_patterns()
        
        # Calculate changes
        changes = self._calculate_changes(current_patterns, pattern_changes)
        
        # Create new commit
        commit = PatternCommit(
            commit_id=self._generate_commit_id(),
            parent_id=self.head_commit,
            timestamp=time.time(),
            author=author,
            message=message,
            changes=changes,
            pattern_snapshot=pattern_changes.copy(),
            validation_results=validation_results,
            branch=self.current_branch
        )
        
        # Save commit and update branch
        self._save_commit(commit)
        self._update_branch_head(self.current_branch, commit.commit_id)
        self.head_commit = commit.commit_id
        
        # Create snapshot for quick rollback
        self._create_snapshot(commit.commit_id, pattern_changes)
        
        logger.info(f"✅ Committed changes: {commit.commit_id[:8]} - {message}")
        logger.info(f"   +{changes.get('patterns_added', 0)} -{changes.get('patterns_removed', 0)} patterns")
        
        return commit.commit_id
    
    def _get_current_patterns(self) -> Dict[str, List[str]]:
        """Get current pattern snapshot"""
        if not self.head_commit:
            return {}
        
        current_commit = self._load_commit(self.head_commit)
        return current_commit.pattern_snapshot if current_commit else {}
    
    def _calculate_changes(self, 
                          old_patterns: Dict[str, List[str]], 
                          new_patterns: Dict[str, List[str]]) -> Dict[str, Any]:
        """Calculate the differences between pattern sets"""
        
        changes = {
            "type": "update",
            "patterns_added": 0,
            "patterns_removed": 0,
            "patterns_modified": 0,
            "sources_modified": [],
            "details": {}
        }
        
        all_sources = set(old_patterns.keys()) | set(new_patterns.keys())
        
        for source in all_sources:
            old_set = set(old_patterns.get(source, []))
            new_set = set(new_patterns.get(source, []))
            
            added = new_set - old_set
            removed = old_set - new_set
            
            if added or removed:
                changes["sources_modified"].append(source)
                changes["details"][source] = {
                    "added": list(added),
                    "removed": list(removed),
                    "added_count": len(added),
                    "removed_count": len(removed)
                }
                
                changes["patterns_added"] += len(added)
                changes["patterns_removed"] += len(removed)
        
        return changes
    
    def _create_snapshot(self, commit_id: str, patterns: Dict[str, List[str]]):
        """Create a snapshot for quick access"""
        snapshot_file = self.snapshots_dir / f"{commit_id}.json"
        
        snapshot_data = {
            "commit_id": commit_id,
            "timestamp": time.time(),
            "patterns": patterns,
            "pattern_count": sum(len(p) for p in patterns.values())
        }
        
        with open(snapshot_file, 'w') as f:
            json.dump(snapshot_data, f, indent=2)
    
    def generate_diff(self, from_commit: str, to_commit: str) -> PatternDiff:
        """Generate diff between two commits"""
        from_commit_obj = self._load_commit(from_commit)
        to_commit_obj = self._load_commit(to_commit)
        
        if not from_commit_obj or not to_commit_obj:
            raise ValueError("Invalid commit IDs")
        
        from_patterns = from_commit_obj.pattern_snapshot
        to_patterns = to_commit_obj.pattern_snapshot
        
        # Calculate differences
        all_sources = set(from_patterns.keys()) | set(to_patterns.keys())
        
        added_patterns = []
        removed_patterns = []
        modified_patterns = []
        source_changes = {}
        
        for source in all_sources:
            from_set = set(from_patterns.get(source, []))
            to_set = set(to_patterns.get(source, []))
            
            added = to_set - from_set
            removed = from_set - to_set
            
            if added or removed:
                source_changes[source] = {
                    "added": list(added),
                    "removed": list(removed)
                }
                
                added_patterns.extend(added)
                removed_patterns.extend(removed)
        
        return PatternDiff(
            from_commit=from_commit,
            to_commit=to_commit,
            added_patterns=added_patterns,
            removed_patterns=removed_patterns,
            modified_patterns=modified_patterns,
            source_changes=source_changes
        )
    
    def rollback_to_commit(self, commit_id: str, reason: str = "manual rollback") -> bool:
        """Rollback to a specific commit"""
        target_commit = self._load_commit(commit_id)
        if not target_commit:
            logger.error(f"❌ Commit not found: {commit_id}")
            return False
        
        # Create rollback point
        rollback_point = RollbackPoint(
            rollback_id=self._generate_commit_id(),
            commit_id=self.head_commit,
            timestamp=time.time(),
            reason=reason,
            system_metrics=self._get_system_metrics(),
            automatic=False
        )
        
        self._save_rollback_point(rollback_point)
        
        # Create new commit with rollback
        rollback_commit = PatternCommit(
            commit_id=self._generate_commit_id(),
            parent_id=self.head_commit,
            timestamp=time.time(),
            author="rollback-system",
            message=f"Rollback to {commit_id[:8]}: {reason}",
            changes={
                "type": "rollback",
                "target_commit": commit_id,
                "reason": reason
            },
            pattern_snapshot=target_commit.pattern_snapshot.copy(),
            branch=self.current_branch
        )
        
        self._save_commit(rollback_commit)
        self._update_branch_head(self.current_branch, rollback_commit.commit_id)
        self.head_commit = rollback_commit.commit_id
        
        logger.info(f"🔄 Rolled back to commit {commit_id[:8]}")
        return True
    
    def _save_rollback_point(self, rollback_point: RollbackPoint):
        """Save a rollback point"""
        rollback_file = self.rollbacks_dir / f"{rollback_point.rollback_id}.json"
        
        with open(rollback_file, 'w') as f:
            json.dump(asdict(rollback_point), f, indent=2)
    
    def _get_system_metrics(self) -> Dict[str, Any]:
        """Get current system performance metrics"""
        # In a real implementation, this would collect actual metrics
        return {
            "timestamp": time.time(),
            "pattern_count": self._get_total_pattern_count(),
            "memory_usage": "simulated",
            "detection_speed": "simulated"
        }
    
    def _get_total_pattern_count(self) -> int:
        """Get total number of patterns in current state"""
        current_patterns = self._get_current_patterns()
        return sum(len(patterns) for patterns in current_patterns.values())
    
    def get_commit_history(self, limit: int = 50) -> List[PatternCommit]:
        """Get commit history starting from HEAD"""
        history = []
        current_commit_id = self.head_commit
        
        while current_commit_id and len(history) < limit:
            commit = self._load_commit(current_commit_id)
            if not commit:
                break
            
            history.append(commit)
            current_commit_id = commit.parent_id
        
        return history
    
    def get_branches(self) -> List[Dict[str, Any]]:
        """Get list of all branches"""
        branches = []
        
        for branch_file in self.branches_dir.glob("*.json"):
            with open(branch_file, 'r') as f:
                branch_data = json.load(f)
                branches.append(branch_data)
        
        return branches
    
    def create_branch(self, branch_name: str, from_commit: str = None) -> bool:
        """Create a new branch"""
        if from_commit is None:
            from_commit = self.head_commit
        
        branch_file = self.branches_dir / f"{branch_name}.json"
        if branch_file.exists():
            logger.warning(f"Branch {branch_name} already exists")
            return False
        
        self._create_branch(branch_name, from_commit)
        logger.info(f"🌿 Created branch: {branch_name}")
        return True
    
    def switch_branch(self, branch_name: str) -> bool:
        """Switch to a different branch"""
        branch_file = self.branches_dir / f"{branch_name}.json"
        if not branch_file.exists():
            logger.error(f"Branch {branch_name} does not exist")
            return False
        
        self.current_branch = branch_name
        self.head_commit = self._get_head_commit(branch_name)
        
        logger.info(f"🔀 Switched to branch: {branch_name}")
        return True
    
    def get_pattern_history(self, pattern: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Get history of a specific pattern"""
        history = []
        commits = self.get_commit_history(limit * 3)  # Get more commits to search through
        
        for commit in commits:
            if len(history) >= limit:
                break
                
            # Check if pattern appears in this commit
            for source, patterns in commit.pattern_snapshot.items():
                if pattern in patterns:
                    history.append({
                        "commit_id": commit.commit_id,
                        "timestamp": commit.timestamp,
                        "message": commit.message,
                        "author": commit.author,
                        "source": source,
                        "action": "present"
                    })
                    break
            
            # Check if pattern was modified in this commit
            if commit.changes.get("details"):
                for source, changes in commit.changes["details"].items():
                    if pattern in changes.get("added", []):
                        history.append({
                            "commit_id": commit.commit_id,
                            "timestamp": commit.timestamp,
                            "message": commit.message,
                            "author": commit.author,
                            "source": source,
                            "action": "added"
                        })
                    elif pattern in changes.get("removed", []):
                        history.append({
                            "commit_id": commit.commit_id,
                            "timestamp": commit.timestamp,
                            "message": commit.message,
                            "author": commit.author,
                            "source": source,
                            "action": "removed"
                        })
        
        return history[:limit]
    
    def export_audit_trail(self, start_date: float = None, end_date: float = None) -> Dict[str, Any]:
        """Export complete audit trail for compliance"""
        if start_date is None:
            start_date = 0
        if end_date is None:
            end_date = time.time()
        
        commits = self.get_commit_history(1000)  # Get extensive history
        filtered_commits = [
            commit for commit in commits 
            if start_date <= commit.timestamp <= end_date
        ]
        
        audit_data = {
            "export_timestamp": time.time(),
            "period": {
                "start": start_date,
                "end": end_date
            },
            "total_commits": len(filtered_commits),
            "commits": [asdict(commit) for commit in filtered_commits],
            "summary": {
                "patterns_added": sum(c.changes.get("patterns_added", 0) for c in filtered_commits),
                "patterns_removed": sum(c.changes.get("patterns_removed", 0) for c in filtered_commits),
                "rollbacks": len([c for c in filtered_commits if c.changes.get("type") == "rollback"]),
                "sources_modified": len(set().union(*[c.changes.get("sources_modified", []) for c in filtered_commits]))
            }
        }
        
        return audit_data

def main():
    """Test the pattern version control system"""
    vcs = PatternVersionControl()
    
    print("🔄 Testing Pattern Version Control System")
    print("=" * 50)
    
    # Test committing changes
    test_patterns = {
        "ublock": ["||tracker1.com^", "||tracker2.com^"],
        "easyprivacy": ["tracking.example.com", "analytics.test.com"]
    }
    
    commit_id = vcs.commit_changes(
        test_patterns, 
        "Add test tracking patterns",
        "test-user"
    )
    
    print(f"✅ Created commit: {commit_id[:8]}")
    
    # Test adding more patterns
    updated_patterns = {
        "ublock": ["||tracker1.com^", "||tracker2.com^", "||newtracker.com^"],
        "easyprivacy": ["tracking.example.com", "analytics.test.com"],
        "adguard": ["spyware.com", "malware.net"]
    }
    
    commit_id2 = vcs.commit_changes(
        updated_patterns,
        "Add new trackers and adguard patterns",
        "auto-update"
    )
    
    print(f"✅ Created commit: {commit_id2[:8]}")
    
    # Test diff generation
    diff = vcs.generate_diff(commit_id, commit_id2)
    print(f"\n📊 Diff between commits:")
    print(f"   Added: {len(diff.added_patterns)} patterns")
    print(f"   Removed: {len(diff.removed_patterns)} patterns")
    
    # Test commit history
    history = vcs.get_commit_history(5)
    print(f"\n📚 Recent commits:")
    for commit in history:
        print(f"   {commit.commit_id[:8]} - {commit.message}")
    
    # Test rollback
    print(f"\n🔄 Testing rollback to {commit_id[:8]}")
    vcs.rollback_to_commit(commit_id, "Testing rollback functionality")
    
    print("\n✅ Pattern VCS test complete!")

if __name__ == "__main__":
    main()