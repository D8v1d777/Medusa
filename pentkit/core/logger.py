from __future__ import annotations
import logging
import os
import sys
from pathlib import Path
from pythonjsonlogger import jsonlogger
from logging.handlers import RotatingFileHandler
from pentkit.core.config import Config

def setup_logger(cfg: Config, session_id: str = "default", log_level: str = "INFO"):
    """
    Set up structured JSON logging to stdout and a rotating file.
    
    :param cfg: Framework configuration.
    :param session_id: Current session UUID for tagging.
    :param log_level: Logging level (INFO, DEBUG, etc.)
    """
    log_dir = Path(os.path.expanduser(cfg.output.log_dir))
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / f"{session_id}.log"

    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Clear existing handlers to avoid duplicates on re-init
    if logger.hasHandlers():
        logger.handlers.clear()

    # JSON Formatter
    # Every log entry: {ts, session_id, pentkit_module, target, level, msg, extra}
    formatter = jsonlogger.JsonFormatter(
        '%(asctime)s %(session_id)s %(pentkit_module)s %(target)s %(levelname)s %(message)s',
        rename_fields={'levelname': 'level', 'asctime': 'timestamp', 'module': 'pentkit_module'},
        static_fields={'session_id': session_id}
    )

    # Stdout Handler
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)

    # Rotating File Handler (10MB max, 5 backups as per spec)
    file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger

def get_module_logger(module_name: str, target: str = "N/A"):
    """Return a logger adapter that includes module and target in every log entry."""
    return logging.LoggerAdapter(
        logging.getLogger(module_name),
        {'pentkit_module': module_name, 'target': target}
    )

__all__ = ["setup_logger", "get_module_logger"]
