import os
import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any, Callable
from flask import request

from .tokens import TokenStore, current_token, default_store, token_is_valid  # noqa: F401

class ApiKeyValidator:
    """
    X-API-KEY validator for the token named by key_env (default APITOKEN5).

    Values come from the rotating token file when it is mounted, else the
    environment (see tokens.py), and any live value is accepted, so a token can
    rotate with no restart and no failed request.
    Bundles params (operator_name, lease_name) for args_str/logging.
    """
    def __init__(self, key_env: str = 'APITOKEN5',
                 logging_report_func: Optional[Callable[[str, str, str], None]] = None):
        self.key_env = key_env
        self.store = default_store()
        self.api_token = self.store.current(key_env)
        if not self.api_token:
            raise ValueError(f"{key_env} env var missing.")
        self.logging_report = logging_report_func or self._default_logging_report
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(os.getenv('LOGGINGLEVEL', 'INFO'))

    def _default_logging_report(self, writing: str, level: str, api_name: str):
        """Fallback if no callback provided."""
        self.logger.log(getattr(logging, level.upper()), writing)

    def _status_dict(self, status_type: str, status_code: int, status_message: str) -> Dict[str, Any]:
        """Standard status format (JSON-compatible)."""
        return {
            'apiStatus': True,
            'requestData': None,
            'statusType': status_type,
            'statusCode': status_code,
            'statusMessage': status_message
        }

    def validate(self, operator_name: Optional[str], lease_name: Optional[str],
                 api_name: str, trace_id: Optional[str] = None,
                 headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        """
        Validates X-API-KEY from headers.
        Params bundled for args_str/logging (as current).
        Returns status dict; raises ValueError with code:msg on fail.
        """
        headers = headers if headers is not None else request.headers

        args = [operator_name or '', lease_name or '']
        args_str = ' | '.join(map(str, args))
        api_key = headers.get('X-API-KEY')
        trace_id = trace_id or headers.get('X-Trace-ID', datetime.now().isoformat()[:8])

        if api_key is None:
            status = self._status_dict('UNDEFINED', 401001, 'X-API-KEY header is not defined.')
            self.logging_report(f'{status["statusType"]} | {status["statusCode"]} | {args_str} | {status["statusMessage"]} | trace:{trace_id}', 'ERROR', api_name)
            raise ValueError(f"{status['statusCode']}: {status['statusMessage']}")

        if not self.store.is_valid(self.key_env, api_key):
            status = self._status_dict('INVALID', 401003, 'Invalid X-API-KEY.')
            self.logging_report(f'{status["statusType"]} | {status["statusCode"]} | {args_str} | {status["statusMessage"]} | trace:{trace_id}', 'ERROR', api_name)
            raise ValueError(f"{status['statusCode']}: {status['statusMessage']}")

        status = self._status_dict('VALID', 200001, 'The X-API-KEY is valid.')
        self.logging_report(f'{status["statusType"]} | {status["statusCode"]} | {args_str} | {status["statusMessage"]} | trace:{trace_id}', 'INFO', api_name)
        return status