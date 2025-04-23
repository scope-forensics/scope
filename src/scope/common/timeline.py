 """
Common timeline functionality for all cloud providers.
"""

class TimelineEvent:
    """
    Base class for timeline events across all cloud providers.
    """
    
    def __init__(self, timestamp, event_type, source, user, details, raw_data=None):
        """
        Initialize a timeline event.
        
        Args:
            timestamp (datetime): When the event occurred
            event_type (str): Type of event
            source (str): Source of the event
            user (str): User who performed the action
            details (str): Event details
            raw_data (dict, optional): Raw event data
        """
        self.timestamp = timestamp
        self.event_type = event_type
        self.source = source
        self.user = user
        self.details = details
        self.raw_data = raw_data
        
    def to_dict(self):
        """
        Convert event to dictionary.
        
        Returns:
            dict: Event as dictionary
        """
        return {
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            'source': self.source,
            'user': self.user,
            'details': self.details
        } 