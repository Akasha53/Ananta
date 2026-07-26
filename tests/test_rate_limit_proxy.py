"""Le rate limiting ne doit pas accepter une IP forgée hors proxy de confiance."""

from starlette.requests import Request

from middleware import RateLimitMiddleware


def _request(client_ip, forwarded_ip):
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/entity/runs",
        "headers": [(b"x-forwarded-for", forwarded_ip.encode())],
        "client": (client_ip, 1234),
        "server": ("ananta", 8010),
        "scheme": "http",
        "query_string": b"",
    }
    return Request(scope)


def test_forwarded_ip_is_ignored_from_untrusted_client(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_IPS", "10.0.0.10")
    middleware = RateLimitMiddleware(lambda scope, receive, send: None)

    assert middleware._get_client_ip(_request("203.0.113.7", "198.51.100.4")) == "203.0.113.7"
    assert middleware._get_client_ip(_request("10.0.0.10", "198.51.100.4")) == "198.51.100.4"
