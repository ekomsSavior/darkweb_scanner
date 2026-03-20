import json
import os
import time
import logging

logger = logging.getLogger(__name__)

STATE_FILE = os.path.join('state', 'scan_state.json')


class ScanState:
    """Persist scan progress for crash recovery"""

    def __init__(self, state_dir='state'):
        self.state_dir = state_dir
        self.state_file = os.path.join(state_dir, 'scan_state.json')
        os.makedirs(state_dir, exist_ok=True)

    def save(self, scan_id, targets, completed_targets, findings, config):
        """Save current scan state after each target"""
        state = {
            'scan_id': scan_id,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'all_targets': targets,
            'completed_targets': completed_targets,
            'remaining_targets': [t for t in targets if t not in completed_targets],
            'findings': findings,
            'config': config,
        }
        try:
            with open(self.state_file, 'w') as f:
                json.dump(state, f, indent=2, default=str)
            logger.debug(f"State saved: {len(completed_targets)}/{len(targets)} targets complete")
        except Exception as e:
            logger.error(f"Failed to save state: {e}")

    def load(self):
        """Load saved scan state if it exists"""
        if not os.path.exists(self.state_file):
            return None
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
            remaining = state.get('remaining_targets', [])
            if remaining:
                return state
            return None  # Scan was complete, nothing to resume
        except Exception as e:
            logger.error(f"Failed to load state: {e}")
            return None

    def clear(self):
        """Remove state file after successful scan completion"""
        if os.path.exists(self.state_file):
            os.remove(self.state_file)
            logger.info("Scan state cleared")

    def has_pending(self):
        """Check if there's an interrupted scan to resume"""
        state = self.load()
        return state is not None
