import logging
import os
from datetime import datetime


class SeparatedLoggingConfig:
    """Centralized logging configuration that separates logs and errors into different files"""
    
    def __init__(self, module_name: str, log_level: str = 'INFO'):
        self.module_name = module_name
        self.log_level = self._parse_log_level(log_level)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.setup_directories()
        self.setup_logging()
    
    def _parse_log_level(self, log_level: str) -> int:
        """Parse string log level to logging constant"""
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL,
            'QUIET': logging.ERROR  # Only show errors in quiet mode
        }
        return level_map.get(log_level.upper(), logging.INFO)
    
    def setup_directories(self):
        """Create logs directory structure if it doesn't exist"""
        self.logs_base_dir = "logs"
        self.log_dir = os.path.join(self.logs_base_dir, "log")
        self.error_dir = os.path.join(self.logs_base_dir, "error")
        
        # Create directories if they don't exist
        for directory in [self.logs_base_dir, self.log_dir, self.error_dir]:
            if not os.path.exists(directory):
                os.makedirs(directory)
    
    def setup_logging(self):
        """Configure logging with separate files for logs and errors"""
        # Generate timestamped filenames only if logging level requires files
        if self.log_level < logging.ERROR:  # Create log files unless in QUIET mode
            log_filename = os.path.join(self.log_dir, f"{self.module_name}_{self.timestamp}.log")
        error_filename = os.path.join(self.error_dir, f"{self.module_name}_{self.timestamp}.error")
        
        # Create logger
        self.logger = logging.getLogger(self.module_name)
        self.logger.setLevel(self.log_level)
        
        # Clear any existing handlers
        self.logger.handlers.clear()
        
        # Create formatters
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        
        # Create file handler for general logs (only if not in QUIET mode)
        if self.log_level < logging.ERROR:
            log_handler = logging.FileHandler(log_filename, encoding='utf-8')
            log_handler.setLevel(max(self.log_level, logging.INFO))  # File logs start at INFO minimum
            log_handler.setFormatter(formatter)
            
            # Create the log file if it doesn't exist
            if not os.path.exists(log_filename):
                with open(log_filename, 'w', encoding='utf-8') as f:
                    pass
            
            self.logger.addHandler(log_handler)
            self.log_file_path = log_filename
        else:
            self.log_file_path = None
        
        
        # Create file handler for errors only (ERROR and above)
        error_handler = logging.FileHandler(error_filename, encoding='utf-8')
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        
        # Create console handler with configurable level
        console_handler = logging.StreamHandler()
        console_handler.setLevel(self.log_level)
        console_handler.setFormatter(formatter)
        
        # Add handlers to logger
        self.logger.addHandler(error_handler)
        self.logger.addHandler(console_handler)
        
        # Store file paths for reference
        self.error_file_path = error_filename
    
    def get_logger(self):
        """Return the configured logger"""
        return self.logger
    
    def get_log_files(self):
        """Return paths to the log files"""
        return {
            'log_file': self.log_file_path,
            'error_file': self.error_file_path
        }


def setup_module_logging(module_name: str, log_level: str = 'INFO'):
    """Convenience function to set up logging for a module"""
    config = SeparatedLoggingConfig(module_name, log_level)
    return config.get_logger(), config.get_log_files()