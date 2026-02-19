"""
log_setup – Structured logging configuration.

Provides a unified `setup_logging()` function that configures either
JSON output (for SIEM / machine parsing) or coloured text output
(for human-readable development), controlled by `config.LOG_MODE`.

Usage::

    from log_setup import get_logger
    logger = get_logger("server")
    logger.info("handshake_complete", latency_ms=12.3, peer="192.168.1.1")
"""

import logging
import sys

import structlog

from config import LOG_MODE

_configured = False


def setup_logging() -> None:
    """Configure structlog + stdlib logging based on LOG_MODE."""
    global _configured
    if _configured:
        return
    _configured = True

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
    ]

    if LOG_MODE == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty())

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ],
    )

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a named structlog logger (calls setup_logging automatically)."""
    setup_logging()
    return structlog.get_logger(name)
