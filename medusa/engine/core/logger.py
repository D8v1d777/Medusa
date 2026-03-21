"""Structured JSON logging."""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from logging.handlers import RotatingFileHandler

try:
    from pythonjsonlogger import jsonlogger
except ImportError:
    jsonlogger = None

from medusa.engine.core.config import Config

__all__ = ["setup_logger", "get_module_logger"]


def setup_logger(
    cfg: Config,
    session_id: str = "default",
    log_level: str = "INFO",
) -> logging.Logger:
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
    logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    if logger.hasHandlers():
        logger.handlers.clear()

    if jsonlogger:
        formatter = jsonlogger.JsonFormatter(
            "%(asctime)s %(session_id)s %(medusa_module)s %(target)s %(levelname)s %(message)s",
            rename_fields={
                "levelname": "level",
                "asctime": "timestamp",
                "module": "medusa_module",
            },
            static_fields={"session_id": session_id},
        )
    else:
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s: %(message)s"
        )

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)

    file_handler = RotatingFileHandler(
        log_file, maxBytes=10 * 1024 * 1024, backupCount=5
    )
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    return logger


def get_module_logger(module_name: str, target: str = "N/A") -> logging.LoggerAdapter:
    """Return a logger adapter that includes module and target in every log entry."""
    return logging.LoggerAdapter(
        logging.getLogger(module_name),
        {"medusa_module": module_name, "target": target},
    )
