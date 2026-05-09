"""
mitm/network_analyzer.py
────────────────────────
Live and offline network traffic analysis using Scapy.

Detects MITM attack indicators:
  1. ARP Spoofing         — duplicate IPs with different MACs
  2. SSL Stripping        — HTTP responses rewriting https to http
  3. TLS Downgrade        — ClientHello negotiating weak versions
  4. DNS Spoofing         — DNS answers deviating from baseline
  5. Cleartext Credentials— HTTP POST/Basic Auth with passwords
  6. Duplicate MACs       — same MAC claiming multiple IPs

Modes:
  run_demo()           — in-memory simulation, no root needed
  analyze_pcap(path)   — read saved .pcap file
  capture_live(iface)  — live sniff (requires root/sudo)
"""

from __future__ import annotations

import json
import logging
import math
import os
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ── Disable IPv6 before any scapy import to avoid sandbox routing bug ─────────
import os as _os
_os.environ.setdefault("SCAPY_USE_PCAPDNET", "0")

from scapy.config import conf as _scapy_conf
_scapy_conf.ipv6_enabled = False
_scapy_conf.verb = 0  # suppress all scapy output

from scapy.layers.l2   import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet      import Raw, Packet

logger = logging.getLogger(__name__)

# ── Optional DNS import (may fail in restricted envs) ─────────────────────────
try:
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    _DNS_AVAILABLE = True
except Exception:
    _DNS_AVAILABLE = False
    logger.warning("Scapy DNS layer unavailable — DNS spoofing detection disabled")


# ── Detection result dataclasses ──────────────────────────────────────────────

@dataclass
class MITMIndicator:
    indicator_id:  str
    attack_type:   str
    severity:      str
    description:   str
    evidence:      str
    source_ip:     Optional[str] = None
    dest_ip:       Optional[str] = None
    timestamp:     str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return {
            "indicator_id": self.indicator_id,
            "attack_type":  self.attack_type,
            "severity":     self.severity,
            "description":  self.description,
            "evidence":     self.evidence,
            "source_ip":    self.source_ip,
            "dest_ip":      self.dest_ip,
            "timestamp":    self.timestamp,
        }


@dataclass
class NetworkAnalysisResult:
    mode:          str
    interface:     Optional[str]
    pcap_file:     Optional[str]
    packets_seen:  int
    duration_secs: float
    indicators:    list[MITMIndicator] = field(default_factory=list)
    risk_score:    float = 0.0

    def to_dict(self) -> dict:
        return {
            "mode":            self.mode,
            "interface":       self.interface,
            "pcap_file":       self.pcap_file,
            "packets_seen":    self.packets_seen,
            "duration_secs":   round(self.duration_secs, 2),
            "risk_score":      round(self.risk_score, 3),
            "indicator_count": len(self.indicators),
            "indicators":      [i.to_dict() for i in self.indicators],
        }


# ── Analyzer ──────────────────────────────────────────────────────────────────

class MITMNetworkAnalyzer:
    """
    Scapy-based MITM detection engine.

    Parameters
    ──────────
    dns_baseline  : known-good { domain → [ip, ...] } for DNS spoofing detection
    """

    WEAK_TLS_VERSIONS = {0x0300, 0x0301, 0x0302}   # SSLv3, TLS 1.0, TLS 1.1
    TLS_VERSION_NAMES = {
        0x0300: "SSLv3",   0x0301: "TLSv1.0",
        0x0302: "TLSv1.1", 0x0303: "TLSv1.2",
        0x0304: "TLSv1.3",
    }
    SEVERITY_WEIGHT = {"HIGH": 3.0, "MEDIUM": 1.5, "LOW": 0.5}
    LAMBDA = 0.25

    def __init__(self, dns_baseline: Optional[dict] = None) -> None:
        self.dns_baseline = dns_baseline or {}
        self._reset()

    def _reset(self) -> None:
        self.arp_table:  dict[str, set[str]] = defaultdict(set)
        self.mac_table:  dict[str, set[str]] = defaultdict(set)
        self.dns_table:  dict[str, set[str]] = defaultdict(set)
        self.indicators: list[MITMIndicator] = []
        self._counter = 0

    # ── Public API ────────────────────────────────────────────────────────────

    def run_demo(self) -> NetworkAnalysisResult:
        """In-memory simulation — no root required."""
        self._reset()
        t0 = time.time()
        packets = self._build_demo_packets()
        for pkt in packets:
            self._process(pkt)
        return self._result("demo", None, None, len(packets), time.time() - t0)

    def analyze_pcap(self, path: str) -> NetworkAnalysisResult:
        """Analyze a saved PCAP file."""
        from scapy.utils import rdpcap
        self._reset()
        t0 = time.time()
        pkts = rdpcap(path)
        for p in pkts:
            self._process(p)
        return self._result("pcap", None, path, len(pkts), time.time() - t0)

    def capture_live(
        self, iface: str = "eth0", count: int = 500, timeout: int = 60
    ) -> NetworkAnalysisResult:
        """Live packet capture — requires root."""
        from scapy.sendrecv import sniff
        self._reset()
        t0 = time.time()
        pkts = sniff(iface=iface, count=count, timeout=timeout,
                     prn=self._process, store=True)
        return self._result("live", iface, None, len(pkts), time.time() - t0)

    # ── Demo packet builder ───────────────────────────────────────────────────

    def _build_demo_packets(self) -> list:
        pkts = []

        # 1. Legitimate ARP reply: 192.168.1.1 → aa:bb:cc:dd:ee:01
        pkts.append(
            Ether(src="aa:bb:cc:dd:ee:01") /
            ARP(op=2, psrc="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01",
                pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
        )

        # 2. ARP spoof: same IP, attacker MAC
        pkts.append(
            Ether(src="de:ad:be:ef:00:01") /
            ARP(op=2, psrc="192.168.1.1", hwsrc="de:ad:be:ef:00:01",
                pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
        )

        # 3. Duplicate MAC claiming a second IP (proxy insertion)
        pkts.append(
            Ether(src="de:ad:be:ef:00:01") /
            ARP(op=2, psrc="192.168.1.50", hwsrc="de:ad:be:ef:00:01",
                pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
        )

        # 4. SSL Strip: HTTP 302 rewriting https → http
        pkts.append(
            IP(src="192.168.1.254", dst="192.168.1.100") /
            TCP(sport=80, dport=54321) /
            Raw(load=(
                b"HTTP/1.1 302 Found\r\n"
                b"Location: http://example.com/login\r\n"
                b"Content-Length: 0\r\n\r\n"
            ))
        )

        # 5. Cleartext credentials in HTTP POST
        pkts.append(
            IP(src="192.168.1.100", dst="192.168.1.1") /
            TCP(sport=54322, dport=80) /
            Raw(load=(
                b"POST /login HTTP/1.1\r\n"
                b"Host: internal.corp.com\r\n"
                b"Content-Type: application/x-www-form-urlencoded\r\n\r\n"
                b"username=admin&password=secret123"
            ))
        )

        # 6. TLS ClientHello with weak version (TLS 1.0 = 0x0301)
        pkts.append(
            IP(src="192.168.1.100", dst="93.184.216.34") /
            TCP(sport=54323, dport=443) /
            Raw(load=bytes([
                0x16,        # Content Type: Handshake
                0x03, 0x01,  # TLS Version: 1.0 (weak)
                0x00, 0x05,  # Length
                0x01, 0x00, 0x00, 0x01, 0x00,
            ]))
        )

        # 7. DNS spoofing (manual bytes — avoids DNS layer import issues)
        # A raw UDP packet that looks like a DNS answer rewriting example.com
        # We test this via our dns_table logic separately
        pkts.append(
            IP(src="192.168.1.254", dst="192.168.1.100") /
            TCP(sport=8080, dport=54324) /
            Raw(load=b"DNS_SPOOF_SIMULATED example.com 10.0.0.99")
        )

        return pkts

    # ── Packet dispatcher ─────────────────────────────────────────────────────

    def _process(self, pkt: Packet) -> None:
        try:
            if pkt.haslayer(ARP):
                self._check_arp(pkt)
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                raw = bytes(pkt[Raw].load)
                self._check_ssl_strip(pkt, raw)
                self._check_tls_downgrade(pkt, raw)
                self._check_cleartext_creds(pkt, raw)
                self._check_simulated_dns(pkt, raw)
            if _DNS_AVAILABLE and pkt.haslayer(DNS):
                self._check_dns(pkt)
        except Exception as exc:
            logger.debug("Packet error: %s", exc)

    # ── Detectors ─────────────────────────────────────────────────────────────

    def _check_arp(self, pkt: Packet) -> None:
        arp = pkt[ARP]
        if arp.op != 2:
            return
        ip  = arp.psrc
        mac = arp.hwsrc.lower()

        # IP claimed by multiple MACs → ARP spoof
        self.arp_table[ip].add(mac)
        if len(self.arp_table[ip]) > 1:
            self._add(
                "ARP_SPOOF", "HIGH",
                "ARP spoofing — same IP claimed by multiple MACs",
                f"IP {ip} has MACs: {', '.join(self.arp_table[ip])}",
                source_ip=ip,
            )

        # Same MAC on multiple IPs → proxy insertion
        self.mac_table[mac].add(ip)
        if len(self.mac_table[mac]) > 1:
            self._add(
                "DUPLICATE_MAC", "MEDIUM",
                "Single MAC associated with multiple IPs — possible MITM proxy insertion",
                f"MAC {mac} claims IPs: {', '.join(self.mac_table[mac])}",
            )

    def _check_dns(self, pkt: Packet) -> None:
        dns = pkt[DNS]
        if dns.qr != 1:
            return
        src = pkt[IP].src if pkt.haslayer(IP) else "?"
        an = dns.an
        while an is not None:
            try:
                domain = (an.rrname.decode() if isinstance(an.rrname, bytes)
                          else str(an.rrname)).rstrip(".")
                answer = str(an.rdata)
                if domain in self.dns_baseline:
                    if answer not in self.dns_baseline[domain]:
                        self._add(
                            "DNS_SPOOF", "HIGH",
                            "DNS answer deviates from known-good baseline",
                            f"{domain} resolved to {answer}, baseline={self.dns_baseline[domain]}",
                            source_ip=src,
                        )
                prev = self.dns_table[domain]
                if prev and answer not in prev:
                    self._add(
                        "DNS_INCONSISTENCY", "MEDIUM",
                        "DNS domain suddenly resolving to a new IP",
                        f"{domain}: was {prev}, now {answer}",
                        source_ip=src,
                    )
                self.dns_table[domain].add(answer)
            except Exception:
                pass
            an = getattr(an, "payload", None)

    def _check_simulated_dns(self, pkt: Packet, raw: bytes) -> None:
        """Handle the simulated DNS packet in the demo."""
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return
        if text.startswith("DNS_SPOOF_SIMULATED"):
            parts = text.split()
            if len(parts) >= 3:
                domain, forged_ip = parts[1], parts[2]
                baseline_ips = self.dns_baseline.get(domain, [])
                self._add(
                    "DNS_SPOOF", "HIGH",
                    "DNS spoofing — domain resolved to unexpected IP",
                    f"{domain} → {forged_ip} (baseline: {baseline_ips or 'unset'})",
                    source_ip=pkt[IP].src if pkt.haslayer(IP) else "?",
                )

    def _check_ssl_strip(self, pkt: Packet, raw: bytes) -> None:
        if raw[:5] not in (b"HTTP/", b"http/"):
            return
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            return
        if ("301" in text[:20] or "302" in text[:20]) and "Location: http://" in text:
            src = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
            for line in text.splitlines():
                if line.startswith("Location:") and "http://" in line:
                    self._add(
                        "SSL_STRIP", "HIGH",
                        "SSL stripping — HTTPS redirect rewritten to HTTP",
                        f"{src}→{dst}: {line.strip()}",
                        source_ip=src, dest_ip=dst,
                    )
                    break

    def _check_tls_downgrade(self, pkt: Packet, raw: bytes) -> None:
        if len(raw) < 3 or raw[0] != 0x16:
            return
        version = (raw[1] << 8) | raw[2]
        if version in self.WEAK_TLS_VERSIONS:
            name = self.TLS_VERSION_NAMES.get(version, f"0x{version:04x}")
            src  = pkt[IP].src if pkt.haslayer(IP) else "?"
            dst  = pkt[IP].dst if pkt.haslayer(IP) else "?"
            port = pkt[TCP].dport if pkt.haslayer(TCP) else "?"
            self._add(
                "TLS_DOWNGRADE", "HIGH",
                f"Weak TLS version negotiated ({name}) — downgrade attack possible",
                f"{src}→{dst}:{port} using {name}",
                source_ip=src, dest_ip=dst,
            )

    def _check_cleartext_creds(self, pkt: Packet, raw: bytes) -> None:
        if pkt.haslayer(TCP) and pkt[TCP].dport not in (80, 8080, 8000):
            return
        try:
            text = raw.decode("utf-8", errors="ignore").lower()
        except Exception:
            return
        for kw in ("password=", "passwd=", "pwd=", "authorization: basic", "secret="):
            if kw in text:
                src = pkt[IP].src if pkt.haslayer(IP) else "?"
                dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
                self._add(
                    "CLEARTEXT_CREDS", "HIGH",
                    "Credentials transmitted over cleartext HTTP",
                    f"{src}→{dst} HTTP payload contains '{kw}'",
                    source_ip=src, dest_ip=dst,
                )
                break

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _add(
        self, attack_type: str, severity: str,
        description: str, evidence: str,
        source_ip: str = None, dest_ip: str = None,
    ) -> None:
        self._counter += 1
        ind = MITMIndicator(
            indicator_id=f"NET-{self._counter:03d}",
            attack_type=attack_type, severity=severity,
            description=description, evidence=evidence,
            source_ip=source_ip, dest_ip=dest_ip,
        )
        key = (attack_type, evidence[:80])
        if key not in {(i.attack_type, i.evidence[:80]) for i in self.indicators}:
            self.indicators.append(ind)
            logger.warning("[%s] %s: %s", severity, attack_type, evidence[:70])

    def _result(self, mode, iface, pcap, n, duration) -> NetworkAnalysisResult:
        w = sum(self.SEVERITY_WEIGHT.get(i.severity, 0) for i in self.indicators)
        risk = min(1.0 - math.exp(-self.LAMBDA * w), 1.0) if w else 0.0
        return NetworkAnalysisResult(
            mode=mode, interface=iface, pcap_file=pcap,
            packets_seen=n, duration_secs=duration,
            indicators=self.indicators, risk_score=risk,
        )
