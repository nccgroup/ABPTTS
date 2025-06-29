import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, MagicMock

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory that gets cleaned up after the test."""
    temp_path = tempfile.mkdtemp()
    yield Path(temp_path)
    shutil.rmtree(temp_path)


@pytest.fixture
def temp_file(temp_dir):
    """Create a temporary file in the temp directory."""
    def _temp_file(name="test_file.txt", content=""):
        file_path = temp_dir / name
        file_path.write_text(content)
        return file_path
    return _temp_file


@pytest.fixture
def mock_config():
    """Provide a mock configuration object."""
    config = MagicMock()
    config.get = Mock(side_effect=lambda key, default=None: {
        "server_url": "http://test.example.com",
        "port": 8080,
        "timeout": 30,
        "debug": False,
        "log_level": "INFO",
    }.get(key, default))
    return config


@pytest.fixture
def mock_settings():
    """Provide mock settings for testing."""
    return {
        "user_agent": "TestAgent/1.0",
        "max_retries": 3,
        "retry_delay": 1,
        "connection_timeout": 10,
        "request_timeout": 30,
        "buffer_size": 4096,
    }


@pytest.fixture
def mock_http_response():
    """Provide a mock HTTP response object."""
    response = MagicMock()
    response.status_code = 200
    response.text = "Mock response text"
    response.content = b"Mock response content"
    response.headers = {"Content-Type": "text/plain"}
    response.json.return_value = {"status": "success"}
    return response


@pytest.fixture
def mock_socket():
    """Provide a mock socket object for network testing."""
    sock = MagicMock()
    sock.recv = Mock(return_value=b"test data")
    sock.send = Mock(return_value=9)  # length of "test data"
    sock.close = Mock()
    return sock


@pytest.fixture
def sample_data_files(temp_dir):
    """Create sample data files in temp directory."""
    data_dir = temp_dir / "data"
    data_dir.mkdir()
    
    # Create sample files similar to project structure
    files = {
        "settings.txt": "key1=value1\nkey2=value2\n",
        "user-agents.txt": "Mozilla/5.0\nChrome/91.0\n",
        "wordlist.txt": "word1\nword2\nword3\n",
    }
    
    for filename, content in files.items():
        (data_dir / filename).write_text(content)
    
    return data_dir


@pytest.fixture
def mock_logger(mocker):
    """Provide a mock logger for testing logging behavior."""
    logger = mocker.Mock()
    logger.debug = mocker.Mock()
    logger.info = mocker.Mock()
    logger.warning = mocker.Mock()
    logger.error = mocker.Mock()
    logger.critical = mocker.Mock()
    return logger


@pytest.fixture(autouse=True)
def reset_environment():
    """Reset environment variables before and after each test."""
    original_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(original_env)


@pytest.fixture
def isolated_filesystem(tmp_path, monkeypatch):
    """Change to a temporary directory for the test."""
    original_cwd = Path.cwd()
    monkeypatch.chdir(tmp_path)
    yield tmp_path
    monkeypatch.chdir(original_cwd)


@pytest.fixture
def capture_logs(caplog):
    """Convenience fixture to capture log messages."""
    with caplog.at_level("DEBUG"):
        yield caplog