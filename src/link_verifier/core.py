import ipaddress
import socket
from urllib.parse import urlparse

import requests


def _is_private_or_local_ip(ip: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_reserved
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
    )


def _hostname_allowed(hostname: str, allowed_domains=None) -> bool:
    if not allowed_domains:
        return True

    normalized_host = hostname.lower().lstrip(".")
    allowed = {d.lower().lstrip(".") for d in allowed_domains}
    return normalized_host in allowed or any(
        normalized_host.endswith("." + d) for d in allowed
    )


def _resolve_ip_addresses(hostname: str):
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return []

    ips = []
    for _, _, _, _, sockaddr in infos:
        if sockaddr and len(sockaddr) > 0:
            ips.append(sockaddr[0])
    return ips


def validate_link(url: str, timeout: int = 10, allowed_domains=None):
    """
    Validate a URL as a likely legitimate external link.

    Returns a dictionary with:
    - legit: bool
    - status: "OK" | "INVALID" | "UNSAFE" | "UNREACHABLE"
    - message: human-readable detail
    - final_url: resolved URL after redirects
    - status_code: HTTP status if available
    """
    allowed_domains = allowed_domains or []

    if not isinstance(url, str) or not url.strip():
        return {
            "legit": False,
            "status": "INVALID",
            "message": "URL is empty.",
            "final_url": None,
            "status_code": None,
        }

    try:
        parsed = urlparse(url)
    except Exception:
        return {
            "legit": False,
            "status": "INVALID",
            "message": "Malformed URL.",
            "final_url": None,
            "status_code": None,
        }

    if parsed.scheme not in ("http", "https"):
        return {
            "legit": False,
            "status": "INVALID",
            "message": "Only http and https are allowed.",
            "final_url": None,
            "status_code": None,
        }

    if not parsed.netloc:
        return {
            "legit": False,
            "status": "INVALID",
            "message": "Missing hostname.",
            "final_url": None,
            "status_code": None,
        }

    hostname = parsed.hostname
    if not hostname:
        return {
            "legit": False,
            "status": "INVALID",
            "message": "Hostname could not be parsed.",
            "final_url": None,
            "status_code": None,
        }

    hostname_lower = hostname.lower()
    if hostname_lower in ("localhost", "127.0.0.1") or hostname_lower.endswith(".localhost"):
        return {
            "legit": False,
            "status": "UNSAFE",
            "message": "Localhost/internal URL is not legitimate.",
            "final_url": None,
            "status_code": None,
        }

    for ip in _resolve_ip_addresses(hostname):
        if _is_private_or_local_ip(ip):
            return {
                "legit": False,
                "status": "UNSAFE",
                "message": f"Private/internal IP resolved for host: {hostname} ({ip})",
                "final_url": None,
                "status_code": None,
            }

    if allowed_domains and not _hostname_allowed(hostname, allowed_domains):
        return {
            "legit": False,
            "status": "UNSAFE",
            "message": "Domain is not in the allowed list.",
            "final_url": None,
            "status_code": None,
        }

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": "LinkVerifier/1.0"},
        )
    except requests.exceptions.Timeout:
        return {
            "legit": False,
            "status": "UNREACHABLE",
            "message": "Request timed out.",
            "final_url": None,
            "status_code": None,
        }
    except requests.exceptions.RequestException as exc:
        return {
            "legit": False,
            "status": "UNREACHABLE",
            "message": f"Network error: {exc}",
            "final_url": None,
            "status_code": None,
        }

    final_url = response.url
    final_hostname = urlparse(final_url).hostname

    if allowed_domains and final_hostname and not _hostname_allowed(final_hostname, allowed_domains):
        return {
            "legit": False,
            "status": "UNSAFE",
            "message": f"Redirected to a non-allowed domain: {final_hostname}",
            "final_url": final_url,
            "status_code": response.status_code,
        }

    if 200 <= response.status_code < 400:
        return {
            "legit": True,
            "status": "OK",
            "message": "Link is reachable and valid.",
            "final_url": final_url,
            "status_code": response.status_code,
        }

    return {
        "legit": False,
        "status": "UNREACHABLE",
        "message": f"Server responded with HTTP {response.status_code}.",
        "final_url": final_url,
        "status_code": response.status_code,
    }
