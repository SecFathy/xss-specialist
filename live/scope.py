"""Scope configuration + enforcement for authorized live-target assessment.

Nothing active happens without an explicit Scope. Every URL is checked against the scope BEFORE a
request; out-of-scope URLs (including redirect targets) are blocked and logged, never followed. A
bounded request budget and a rate limit cap activity. The scope never auto-expands.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class Scope:
    base_url: str
    allowed_hosts: list[str] = field(default_factory=list)
    allowed_subdomains: list[str] = field(default_factory=list)   # suffixes, e.g. "example.com"
    allowed_prefixes: list[str] = field(default_factory=list)     # URL path prefixes
    excluded_paths: list[str] = field(default_factory=list)
    max_depth: int = 3
    max_requests: int = 300
    rate_limit_rps: float = 5.0
    enable_header_injection: bool = False
    auth: dict = field(default_factory=dict)                      # only when explicitly supplied
    extra_headers: dict = field(default_factory=dict)
    cookies: list[dict] = field(default_factory=list)

    def __post_init__(self):
        host = urlparse(self.base_url).hostname
        if host and host not in self.allowed_hosts:
            self.allowed_hosts.append(host)
        if not self.allowed_prefixes:
            self.allowed_prefixes = [urlparse(self.base_url).path or "/"]

    def in_scope(self, url: str) -> tuple[bool, str]:
        try:
            p = urlparse(url)
        except Exception:
            return False, "unparseable"
        if p.scheme not in ("http", "https"):
            return False, f"scheme {p.scheme!r}"
        host = p.hostname or ""
        host_ok = host in self.allowed_hosts or any(
            host == d or host.endswith("." + d) for d in self.allowed_subdomains)
        if not host_ok:
            return False, f"host {host!r} not allowed"
        path = p.path or "/"
        if any(path.startswith(x) for x in self.excluded_paths):
            return False, "excluded path"
        if self.allowed_prefixes and not any(path.startswith(x) for x in self.allowed_prefixes):
            return False, "outside allowed prefixes"
        return True, "in_scope"


@dataclass
class Enforcer:
    """Wraps a Scope with the live request budget, rate limiter, and request/blocked logs."""
    scope: Scope
    requests_made: int = 0
    request_log: list[dict] = field(default_factory=list)
    blocked_log: list[dict] = field(default_factory=list)
    _last_req_t: float = 0.0

    def budget_left(self) -> int:
        return max(0, self.scope.max_requests - self.requests_made)

    def check(self, url: str, kind: str = "get", depth: int | None = None) -> tuple[bool, str]:
        ok, reason = self.scope.in_scope(url)
        if not ok:
            self.blocked_log.append({"url": url, "reason": reason, "kind": kind})
            return False, reason
        if depth is not None and depth > self.scope.max_depth:
            return False, "max_depth"
        if self.budget_left() <= 0:
            return False, "max_requests"
        return True, "ok"

    def note_request(self, url: str, final_url: str = "", status: int | None = None,
                     kind: str = "get", depth: int | None = None):
        """Record a request and enforce the rate limit. Also checks the FINAL url (post-redirect)
        stayed in scope; an out-of-scope redirect is logged as blocked."""
        now = time.time()
        min_gap = 1.0 / max(0.1, self.scope.rate_limit_rps)
        wait = self._last_req_t + min_gap - now
        if wait > 0:
            time.sleep(wait)
        self._last_req_t = time.time()
        self.requests_made += 1
        rec = {"url": url, "final_url": final_url or url, "status": status,
               "kind": kind, "depth": depth, "n": self.requests_made}
        self.request_log.append(rec)
        if final_url and final_url != url:
            ok, reason = self.scope.in_scope(final_url)
            if not ok:
                self.blocked_log.append({"url": final_url, "reason": f"redirect_out_of_scope:{reason}",
                                         "from": url})
                rec["redirect_blocked"] = True
        return rec
