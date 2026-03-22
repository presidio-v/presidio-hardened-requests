from __future__ import annotations

import logging

import pytest
import responses

import presidio_requests


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Reset the module-level session's rate limiter between tests."""
    presidio_requests._session.rate_limiter.reset()
    yield
    presidio_requests._session.rate_limiter.reset()


@pytest.fixture()
def mocked_responses():
    """Activate the ``responses`` mock for HTTP calls."""
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.fixture()
def caplog_info(caplog):
    with caplog.at_level(logging.DEBUG, logger="presidio_requests"):
        yield caplog
