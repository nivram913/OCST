import logging
import requests

import pytest

logger = logging.getLogger()
logger.setLevel(logging.INFO)


@pytest.mark.authorization
class TestAuthorization:
    pass
