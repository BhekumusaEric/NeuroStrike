"""
Logger Module
Handles logging for the NeuroStrike application
"""

import os
import logging
import yaml
from logging.handlers import RotatingFileHandler
from typing import Optional

# Global logger dictionary
loggers = {}

def setup_logger(name: str, level: str = "INFO") -> logging.Logger:
    """
    Set up a logger with the specified name and level
    
    Args:
        name: Name of the logger
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        
    Returns:
        Configured logger instance
    """
    # Convert level string to logging level
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    
    # Load configuration
    config = _load_config()
    log_dir = config.get("logging", {}).get("log_dir", "data/logs")
    max_log_size = config.get("logging", {}).get("max_log_size", 10) * 1024 * 1024  # Convert MB to bytes
    backup_count = config.get("logging", {}).get("backup_count", 5)
    
    # Create logger
    logger = logging.getLogger(name)
    logger.setLevel(numeric_level)
    
    # Clear existing handlers
    if logger.handlers:
        logger.handlers.clear()
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # Create file handler
    try:
        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Create file handler
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, f"{name}.log"),
            maxBytes=max_log_size,
            backupCount=backup_count
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        logger.error(f"Failed to set up file handler: {e}")
    
    # Store logger in global dictionary
    loggers[name] = logger
    
    return logger

def get_logger(name: str) -> logging.Logger:
    """
    Get a logger with the specified name
    If the logger doesn't exist, create it
    
    Args:
        name: Name of the logger
        
    Returns:
        Logger instance
    """
    if name in loggers:
        return loggers[name]
    else:
        return setup_logger(name)

def _load_config() -> dict:
    """Load configuration from YAML file"""
    try:
        with open("config/settings.yaml", "r") as file:
            return yaml.safe_load(file)
    except Exception:
        # Return default configuration if file not found
        return {
            "logging": {
                "level": "INFO",
                "log_dir": "data/logs",
                "max_log_size": 10,
                "backup_count": 5
            }
        }
