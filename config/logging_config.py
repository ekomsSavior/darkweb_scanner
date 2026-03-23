"""Logging configuration for the scanner.

FIX: This file was empty. Every module creates loggers via logging.getLogger()
but logging was never configured, so all log messages went nowhere.
This sets up a basic config that writes WARNING+ to stderr by default,
and DEBUG+ to a file when LOG_FILE env var is set.
"""
import logging
import os


def setup_logging(level=None):
    log_level = level or os.environ.get('LOG_LEVEL', 'WARNING')

    handlers = [logging.StreamHandler()]

    log_file = os.environ.get('LOG_FILE')
    if log_file:
        handlers.append(logging.FileHandler(log_file))

    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.WARNING),
        format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
        handlers=handlers,
    )
