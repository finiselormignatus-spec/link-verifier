from unittest.mock import patch

from link_verifier.core import validate_link


class DummyResponse:
    def __init__(self, status_code=200, url="https://example.com"):
        self.status_code = status_code
        self.url = url


def test_invalid_url():
    result = validate_link("not-a-url")
    assert result["status"] == "INVALID"
    assert result["legit"] is False


def test_localhost_is_unsafe():
    result = validate_link("http://localhost:8000")
    assert result["status"] == "UNSAFE"
    assert result["legit"] is False


def test_allowed_domain_blocked():
    result = validate_link("https://evil.com", allowed_domains=["example.com"])
    assert result["status"] == "UNSAFE"
    assert result["legit"] is False


def test_valid_url_success():
    with patch("link_verifier.core.requests.get", return_value=DummyResponse(200, "https://example.com")):
        result = validate_link("https://example.com")
    assert result["status"] == "OK"
    assert result["legit"] is True


def test_redirect_to_disallowed_domain():
    with patch(
        "link_verifier.core.requests.get",
        return_value=DummyResponse(302, "https://evil.com/redirect"),
    ):
        result = validate_link("https://example.com", allowed_domains=["example.com"])
    assert result["status"] == "UNSAFE"
    assert result["legit"] is False
