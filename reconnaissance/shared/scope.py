"""Target scope derived from the single ``--url`` input.

The scope is the registrable domain of the target URL: the apex domain and
every subdomain of it.  ``https://pax-poi-webapp.grab.com/`` therefore scopes
to ``grab.com`` and ``*.grab.com``.  Anything else is out of scope and is never
requested by any module.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .url_normalization import host_of, normalize_url

# Multi-label public suffixes relevant to the regions Bugchestrator targets.
# A full Public Suffix List is not vendored; single-label TLDs are handled by
# the generic "last two labels" rule.
MULTI_LABEL_PUBLIC_SUFFIXES = {
    "co.id", "or.id", "ac.id", "go.id", "web.id", "my.id", "biz.id", "net.id", "sch.id", "ponpes.id",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "com.my", "net.my", "org.my", "gov.my", "edu.my",
    "co.th", "in.th", "or.th", "go.th", "ac.th",
    "com.vn", "net.vn", "org.vn", "gov.vn", "edu.vn",
    "com.ph", "net.ph", "org.ph", "gov.ph", "edu.ph",
    "com.mm", "com.kh", "com.la", "com.bn",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "go.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.hk", "org.hk", "net.hk", "gov.hk",
    "com.tw", "org.tw", "net.tw",
    "co.in", "net.in", "org.in", "gov.in", "ac.in",
    "com.br", "net.br", "org.br", "gov.br",
    "com.mx", "org.mx", "gob.mx",
    "co.za", "org.za", "gov.za",
    "com.tr", "org.tr", "gov.tr",
    "com.sa", "com.eg", "com.pk", "com.bd", "com.ng", "co.ke",
    "github.io", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev",
    "appspot.com", "cloudfront.net", "azurewebsites.net", "firebaseapp.com", "web.app",
}


def registrable_domain(host: str) -> str:
    """Registrable domain (``eTLD+1``) of ``host``; IP addresses map to themselves."""
    host = host.lower().rstrip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in MULTI_LABEL_PUBLIC_SUFFIXES:
        return ".".join(labels[-3:])
    return last_two


@dataclass(frozen=True)
class TargetScope:
    target_url: str
    target_host: str
    target_origin: str
    domain: str

    @classmethod
    def from_url(cls, url: str) -> "TargetScope":
        normalized = normalize_url(url)
        if not normalized:
            raise ValueError(f"not an absolute http(s) URL: {url!r}")
        host = host_of(normalized)
        scheme = normalized.split("://", 1)[0]
        port_part = normalized.split("://", 1)[1].split("/", 1)[0]
        return cls(
            target_url=normalized,
            target_host=host,
            target_origin=f"{scheme}://{port_part}",
            domain=registrable_domain(host),
        )

    def host_in_scope(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return host == self.domain or host.endswith("." + self.domain)

    def url_in_scope(self, url: str) -> bool:
        host = host_of(url)
        return bool(host) and self.host_in_scope(host)

    def url_on_target_host(self, url: str) -> bool:
        return host_of(url) == self.target_host

    def describe(self) -> dict:
        return {
            "target_url": self.target_url,
            "target_host": self.target_host,
            "registrable_domain": self.domain,
            "in_scope_hosts": [self.domain, f"*.{self.domain}"],
        }
