from abc import ABC, abstractmethod

class BaseCheck(ABC):
    """Abstract base class for all vulnerability checks"""
    
    def __init__(self):
        self.name = "Base Check"
        self.description = "Base vulnerability check class"
        self.enabled = True
        self.severity_map = {
            'critical': 4,
            'high': 3,
            'medium': 2,
            'low': 1,
            'info': 0
        }
    
    @abstractmethod
    def run(self, target, tor_session, config=None):
        """
        Run the check against a target
        
        Args:
            target: URL or hostname to check
            tor_session: TorSession instance for making requests
            config: Dictionary with scan configuration
            
        Returns:
            List of finding dictionaries, each containing:
            - check: Name of the check
            - severity: critical/high/medium/low/info
            - finding: Short description
            - detail: More detailed information
            - url: URL where finding was found (optional)
            - data: Any additional data (optional)
        """
        pass
    
    def get_severity_level(self, severity):
        """Convert severity string to numeric level for sorting"""
        return self.severity_map.get(severity.lower(), 0)
