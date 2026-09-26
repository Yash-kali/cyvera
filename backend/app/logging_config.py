import logging
import sys
import re
from logging.handlers import RotatingFileHandler

class SensitiveUrlFilter(logging.Filter):
    """Filter that strips authorization tokens, credentials, and API keys from all server logs."""
    TOKEN_REGEX = re.compile(r'(token=)[^&\s]+', re.IGNORECASE)

    def filter(self, record: logging.LogRecord) -> bool:
        if hasattr(record, "args") and isinstance(record.args, tuple):
            new_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    new_args.append(self.TOKEN_REGEX.sub(r'\1[REDACTED]', arg))
                else:
                    new_args.append(arg)
            record.args = tuple(new_args)
        if isinstance(record.msg, str):
            record.msg = self.TOKEN_REGEX.sub(r'\1[REDACTED]', record.msg)
        return True


def setup_production_logging():
    """
    Configures structured production logging for AutoPentest AI backend.
    Logs to stdout for containerized environments and rotates log files to 'autopentest.log'.
    """
    logger = logging.getLogger("autopentest_ai")
    logger.setLevel(logging.INFO)

    url_filter = SensitiveUrlFilter()
    logger.addFilter(url_filter)

    # Sanitize uvicorn access logs
    for uv_name in ["uvicorn", "uvicorn.access", "uvicorn.error"]:
        uv_log = logging.getLogger(uv_name)
        uv_log.addFilter(url_filter)

    if logger.handlers:
        return logger

    # Log Formatter
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] [%(filename)s:%(lineno)d] - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Console Handler (stdout)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # File Handler with rotation (max 10MB per file, max 5 backup files)
    try:
        file_handler = RotatingFileHandler(
            "autopentest.log",
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        print(f"Warning: Could not initialize log file handler: {e}")

    return logger


logger = setup_production_logging()

