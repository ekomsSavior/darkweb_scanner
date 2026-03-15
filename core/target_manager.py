import json
import csv
from typing import List, Dict, Any
import logging

logger = logging.getLogger(__name__)

class TargetManager:
    def __init__(self):
        self.targets = []  # List of target URLs
        self.target_metadata = {}  # Dict with target as key, metadata as value
        
    def load_from_file(self, filename: str) -> List[str]:
        """Load targets from a text file (one per line)"""
        try:
            with open(filename, 'r') as f:
                self.targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            logger.info(f"Loaded {len(self.targets)} targets from {filename}")
            return self.targets
        except Exception as e:
            logger.error(f"Failed to load targets from {filename}: {e}")
            return []
    
    def load_from_json(self, filename: str) -> List[str]:
        """Load targets from JSON file with metadata"""
        try:
            with open(filename, 'r') as f:
                data = json.load(f)
                if isinstance(data, list):
                    self.targets = data
                elif isinstance(data, dict) and 'targets' in data:
                    self.targets = data['targets']
                    self.target_metadata = data.get('metadata', {})
            logger.info(f"Loaded {len(self.targets)} targets from JSON {filename}")
            return self.targets
        except Exception as e:
            logger.error(f"Failed to load JSON targets: {e}")
            return []
    
    def add_target(self, target: str, metadata: Dict = None):
        """Add a single target with optional metadata - NO FUCKING VALIDATION"""
        # Strip whitespace and just add the damn thing
        target = target.strip()
        if not target:
            return
        
        # If it doesn't have http://, add it
        if not target.startswith('http://') and not target.startswith('https://'):
            target = 'http://' + target
            
        if target not in self.targets:
            self.targets.append(target)
            if metadata:
                self.target_metadata[target] = metadata
            logger.info(f"Added target: {target}")
        else:
            logger.debug(f"Target already exists: {target}")
    
    def remove_target(self, target: str):
        """Remove a target"""
        if target in self.targets:
            self.targets.remove(target)
            if target in self.target_metadata:
                del self.target_metadata[target]
            logger.info(f"Removed target: {target}")
    
    def get_targets(self) -> List[str]:
        """Get all targets"""
        return self.targets
    
    def get_metadata(self, target: str) -> Dict:
        """Get metadata for a specific target"""
        return self.target_metadata.get(target, {})
    
    def get_count(self) -> int:
        """Get number of targets"""
        return len(self.targets)
    
    def clear(self):
        """Clear all targets"""
        self.targets = []
        self.target_metadata = {}
        logger.info("Cleared all targets")
    
    def import_from_intel_report(self, filename: str):
        """Import targets from your threat intel report format"""
        # This is where you'd parse your PDF/JSON reports
        # For now, a simple implementation
        try:
            with open(filename, 'r') as f:
                # Simple extraction of .onion URLs
                import re
                content = f.read()
                onion_urls = re.findall(r'[a-zA-Z0-9]{56}\.onion', content)
                for url in onion_urls:
                    self.add_target(f"http://{url}")
            logger.info(f"Imported {len(onion_urls)} targets from intel report")
        except Exception as e:
            logger.error(f"Failed to import intel report: {e}")
