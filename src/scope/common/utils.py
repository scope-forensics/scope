"""
Common utility functions for the Cloud Forensics package.
"""

import logging
import os
import sys
from datetime import datetime

def setup_logging(log_level=logging.INFO, log_file=None):
    """
    Set up logging configuration.
    
    Args:
        log_level (int): Logging level (default: INFO)
        log_file (str, optional): Path to log file. If None, logs to console only.
    """
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(logging.Formatter(log_format))
    root_logger.addHandler(console_handler)
    
    # Add file handler if specified
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(log_format))
        root_logger.addHandler(file_handler)
        
def format_timestamp(timestamp, format_str='%Y-%m-%d %H:%M:%S'):
    """
    Format a timestamp into a human-readable string.
    
    Args:
        timestamp (datetime): Datetime object to format
        format_str (str): Format string for strftime
        
    Returns:
        str: Formatted timestamp string
    """
    if not timestamp:
        return 'N/A'
        
    if isinstance(timestamp, str):
        try:
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except ValueError:
            return timestamp
            
    return timestamp.strftime(format_str) 