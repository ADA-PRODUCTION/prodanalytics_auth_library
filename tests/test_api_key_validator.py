# tests/test_api_key_validator.py
import os
import pytest
from unittest.mock import Mock, patch
from prodanalytics_auth_library import ApiKeyValidator

class TestApiKeyValidator:
    @pytest.fixture
    def validator(self):
        os.environ['APITOKEN5'] = 'test-key'
        yield ApiKeyValidator()
        del os.environ['APITOKEN5']

    @pytest.fixture
    def mock_headers(self):
        return {'X-API-KEY': 'test-key'}

    def test_init_success(self, validator):
        assert validator.api_token == 'test-key'

    def test_init_missing_env(self):
        with pytest.raises(ValueError, match='MISSING_KEY env var missing.'):
            ApiKeyValidator(key_env='MISSING_KEY')

    def test_validate_valid_key(self, validator, mock_headers):
        mock_log = Mock()
        validator.logging_report = mock_log
        # Pass headers directly instead of patching flask.request
        status = validator.validate('OpCo', 'Lease1', 'parameterspost', headers=mock_headers)
        assert status['statusType'] == 'VALID'
        assert status['statusCode'] == 200001
        mock_log.assert_called_once()

    def test_validate_invalid_key(self, validator):
        mock_log = Mock()
        validator.logging_report = mock_log
        with pytest.raises(ValueError, match='401003: Invalid X-API-KEY.'):
            validator.validate('OpCo', 'Lease1', 'parameterspost', headers={'X-API-KEY': 'wrong-key'})
        mock_log.assert_called_once()

    def test_validate_missing_key(self, validator):
        mock_log = Mock()
        validator.logging_report = mock_log
        with pytest.raises(ValueError, match='401001: X-API-KEY header is not defined.'):
            validator.validate('OpCo', 'Lease1', 'parameterspost', headers={})
        mock_log.assert_called_once()

    def test_validate_none_params(self, validator, mock_headers):
        status = validator.validate(None, None, 'userregistryget', headers=mock_headers)
        assert status['statusType'] == 'VALID'

    def test_validate_custom_headers(self, validator):
        status = validator.validate('OpCo', 'Lease1', 'parameterspost', headers={'X-API-KEY': 'test-key'})
        assert status['statusType'] == 'VALID'

    def test_logging_callback(self, validator, mock_headers):
        mock_log = Mock()
        validator.logging_report = mock_log
        status = validator.validate('OpCo', 'Lease1', 'parameterspost', headers=mock_headers)
        assert status['statusType'] == 'VALID'
        mock_log.assert_called_once()  # Verifies callback invocation