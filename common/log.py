import logging
import os
from datetime import datetime
from typing import Union

from pythonjsonlogger import jsonlogger

LoggerType = Union[logging.Logger, logging.LoggerAdapter]
SCAN_ID = os.environ.get("SCAN_ID", "unknown")
UBER_TRACE_ID = os.environ.get("UBER_TRACE_ID", None)


class MyLoggerAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        self_extra = self.extra or {}
        extra_kwargs = kwargs.get("extra", {})
        kwargs["extra"] = {**self_extra, **extra_kwargs}
        return msg, kwargs


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record, message_dict)
        if not log_record.get("timestamp"):
            if hasattr(record, "created"):
                ts = datetime.fromtimestamp(record.created)
            else:
                # this doesn't use record.created, so it is slightly off
                ts = datetime.utcnow()
            log_record["timestamp"] = ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        if log_record.get("level"):
            log_record["level"] = log_record["level"].upper()
        else:
            log_record["level"] = record.levelname


def configure_logging(name: str) -> LoggerType:
    logger = logging.getLogger(name)
    handler = logging.StreamHandler()
    handler.setLevel(logging.INFO)
    formatter = CustomJsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    context_logger = MyLoggerAdapter(logger, {"traceid": SCAN_ID})
    # Extractor enables json log formatter based on this environment variable which it will inherit
    # from current process.
    os.environ["LOG_FORMAT"] = "json"
    return context_logger
