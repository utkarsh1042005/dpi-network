import fnmatch
from typing import Optional, Set
from models import AppType


def _sni_to_app_type(sni: str) -> AppType:
    """Map a domain name to an application type using substring matching.

    This is a simplified version of the approach used by nDPI and
    other real-world DPI engines. The domain patterns are checked
    case-insensitively against known domains.

    The matching is ordered:
    1. First check for streaming/social patterns
    2. Then check for individual services
    3. Fall back to generic categories (cloud, CDN, etc.)
    """
    sni_lower = sni.lower()

    # Streaming
    if any(d in sni_lower for d in [
        'youtube', 'ytimg', 'youtu.be', 'googlevideo',
        'netflix', 'nflxvideo', 'nflxext', 'nflximg',
        'hulu', 'disney', 'hotstar', 'vimeo',
        'twitch', 'tv'
    ]):
        return AppType.STREAMING

    # Social Media
    if any(d in sni_lower for d in [
        'facebook', 'fbcdn', 'fb.com', 'instagram', 'cdninstagram',
        'twitter', 't.co', 'twimg', 'linkedin',
        'tiktok', 'snapchat', 'reddit', 'pinterest',
        'whatsapp', 'telegram', 'discord', 'signal'
    ]):
        return AppType.SOCIAL_MEDIA

    # Google services
    if any(d in sni_lower for d in [
        'google', 'gmail', 'googleapis', 'googleusercontent',
        'googleanalytics', 'googlesyndication', 'googleadservices',
        'googleadsserving', 'gstatic', 'ggpht', 'doubleclick'
    ]):
        return AppType.GOOGLE

    # Amazon/AWS
    if any(d in sni_lower for d in [
        'amazon', 'aws', 'cloudfront', 'amazonaws'
    ]):
        return AppType.AMAZON

    # Apple
    if any(d in sni_lower for d in [
        'apple', 'icloud', 'itunes', 'appstore'
    ]):
        return AppType.APPLE

    # Microsoft
    if any(d in sni_lower for d in [
        'microsoft', 'msn', 'office', 'live.com', 'outlook',
        'azure', 'bing', 'windows', 'skype', 'teams'
    ]):
        return AppType.MICROSOFT

    # CDN / Cloudflare
    if any(d in sni_lower for d in [
        'cloudflare', 'akamai', 'fastly', 'cdn.',
        'cloudfront', 'stackpath'
    ]):
        return AppType.CDN

    # GitHub
    if 'github' in sni_lower:
        return AppType.GITHUB

    # Spotify
    if 'spotify' in sni_lower:
        return AppType.SPOTIFY

    # Discord
    if 'discord' in sni_lower:
        return AppType.DISCORD

    # Malware/Tracking
    if any(d in sni_lower for d in [
        'malware', 'phishing', 'tracker', 'analytics',
        'doubleclick', 'scorecardresearch'
    ]):
        return AppType.AD_TRACKER

    # Generic HTTPS
    return AppType.HTTPS


def _port_to_app_type(dst_port: int) -> AppType:
    """Fallback: classify by port number if no SNI/HTTP/DNS info."""
    port_map = {
        80: AppType.HTTP,
        443: AppType.HTTPS,
        53: AppType.DNS,
        22: AppType.SSH,
        21: AppType.FTP,
        25: AppType.MAIL,
        110: AppType.MAIL,
        143: AppType.MAIL,
        993: AppType.MAIL,
        995: AppType.MAIL,
        3306: AppType.CLOUD,
        27015: AppType.GAMING,
        27016: AppType.GAMING,
    }
    return port_map.get(dst_port, AppType.UNKNOWN)


class RuleEngine:
    """Manages blocking rules and makes allow/deny decisions.

    Four rule types, checked in priority order:
    1. IP blocking — exact match on source IP
    2. Port blocking — exact match on destination port
    3. Domain blocking — exact or wildcard match ('*.example.com')
    4. Application blocking — by AppType enum
    """

    def __init__(self):
        self._blocked_ips: Set[str] = set()
        self._blocked_ports: Set[int] = set()
        self._blocked_apps: Set[AppType] = set()
        self._blocked_domains: Set[str] = set()
        self._blocked_domain_patterns: Set[str] = set()

    def block_ip(self, ip: str):
        self._blocked_ips.add(ip)

    def block_port(self, port: int):
        self._blocked_ports.add(port)

    def block_app(self, app: AppType):
        self._blocked_apps.add(app)

    def block_domain(self, domain: str):
        domain_lower = domain.lower()
        if '*' in domain_lower:
            self._blocked_domain_patterns.add(domain_lower)
        else:
            self._blocked_domains.add(domain_lower)

    def unblock_ip(self, ip: str):
        self._blocked_ips.discard(ip)

    def unblock_port(self, port: int):
        self._blocked_ports.discard(port)

    def unblock_app(self, app: AppType):
        self._blocked_apps.discard(app)

    def unblock_domain(self, domain: str):
        domain_lower = domain.lower()
        if '*' in domain_lower:
            self._blocked_domain_patterns.discard(domain_lower)
        else:
            self._blocked_domains.discard(domain_lower)

    def load_from_file(self, filepath: str):
        """Load rules from a text file.

        Format:
            block-ip 192.168.1.100
            block-port 22
            block-app YOUTUBE
            block-domain *.example.com
        """
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split(None, 1)
                if len(parts) != 2:
                    continue

                cmd, value = parts
                if cmd == 'block-ip':
                    self.block_ip(value)
                elif cmd == 'block-port':
                    try:
                        self.block_port(int(value))
                    except ValueError:
                        pass
                elif cmd == 'block-app':
                    try:
                        self.block_app(AppType[value.upper()])
                    except KeyError:
                        pass
                elif cmd == 'block-domain':
                    self.block_domain(value)

    def should_block(
        self,
        src_ip: str,
        dst_port: int,
        app_type: Optional[AppType] = None,
        domain: Optional[str] = None,
    ) -> bool:
        """Check if a packet should be blocked.

        Priority order (from original C++ code):
        1. IP blocking — checked first (fastest)
        2. Port blocking
        3. Application blocking
        4. Domain blocking (slowest — has wildcard matching)

        Returns True if the packet should be dropped.
        """
        if src_ip in self._blocked_ips:
            return True

        if dst_port in self._blocked_ports:
            return True

        if app_type is not None and app_type in self._blocked_apps:
            return True

        if domain is not None:
            domain_lower = domain.lower()
            if domain_lower in self._blocked_domains:
                return True
            for pattern in self._blocked_domain_patterns:
                if fnmatch.fnmatch(domain_lower, pattern):
                    return True

        return False

    @property
    def has_rules(self) -> bool:
        return bool(
            self._blocked_ips or self._blocked_ports or
            self._blocked_apps or self._blocked_domains or
            self._blocked_domain_patterns
        )

    def summary(self) -> list[str]:
        lines = []
        if self._blocked_ips:
            lines.append(f"  Blocked IPs: {', '.join(sorted(self._blocked_ips))}")
        if self._blocked_ports:
            lines.append(f"  Blocked Ports: {', '.join(str(p) for p in sorted(self._blocked_ports))}")
        if self._blocked_apps:
            lines.append(f"  Blocked Apps: {', '.join(a.name.lower() for a in sorted(self._blocked_apps))}")
        if self._blocked_domains:
            lines.append(f"  Blocked Domains: {', '.join(sorted(self._blocked_domains))}")
        if self._blocked_domain_patterns:
            lines.append(f"  Blocked Patterns: {', '.join(sorted(self._blocked_domain_patterns))}")
        return lines
