"""
Logging utility module
Provides structured logging for the scanner
"""

import logging
import sys
from typing import Optional
from pathlib import Path
from datetime import datetime

def setup_logger(
    name: str = "apivulnminer",
    level: str = "INFO",
    log_file: Optional[str] = None,
    verbose: bool = False
) -> logging.Logger:
    """Setup structured logger for the application."""
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatter
    if verbose:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        )
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        try:
            # Create log directory if it doesn't exist
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"Failed to setup file logging: {e}")
    
    return logger

def get_logger(name: str) -> logging.Logger:
    """Get logger instance."""
    return logging.getLogger(f"apivulnminer.{name}")

# Default logger instance
default_logger = setup_logger() 