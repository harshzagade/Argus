"""Network collector: new outbound TCP connections via /proc/net/tcp{,6}.

Parses the kernel's hex socket tables directly (no ss/netstat dependency).
A socket counts as "outbound" when its local port is in the ephemeral range
(>= 32768) and the remote endpoint is not a listener/loopback address.
Only ESTABLISHED (01) and SYN_SENT (02) sockets are considered.
"""

import logging
import os
import socket
import struct
import time

from . import BaseCollector

log = logging.getLogger("argus.network")

_ST_ESTABLISHED = "01"
_ST_SYN_SENT = "02"
_EPHEMERAL_MIN = 32768
_MAX_EVENTS_PER_CYCLE = 200


def _decode_ipv4(hexword):
    # /proc/net/tcp stores each 32-bit word little-endian: "0100007F" -> 127.0.0.1
    return socket.inet_ntoa(struct.pack("<L", int(hexword, 16)))


def _decode_ipv6(hexstr):
    # 32 hex chars = 4 little-endian 32-bit words.
    raw = b"".join(
        struct.pack("<L", int(hexstr[i:i + 8], 16)) for i in range(0, 32, 8)
    )
    return socket.inet_ntop(socket.AF_INET6, raw)


def _is_loopback(ip):
    return ip.startswith("127.") or ip == "::1"


def _parse_table(path, proto, decode_ip):
    """Yield (local_ip, local_port, rem_ip, rem_port, state) tuples."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except FileNotFoundError:
        return  # e.g. no tcp6 table; not an error
    except OSError as exc:
        log.warning("cannot read %s: %s", path, exc)
        return
    for line in lines[1:]:  # skip header
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            local_ip_hex, local_port_hex = parts[1].rsplit(":", 1)
            rem_ip_hex, rem_port_hex = parts[2].rsplit(":", 1)
            state = parts[3]
            yield (decode_ip(local_ip_hex), int(local_port_hex, 16),
                   decode_ip(rem_ip_hex), int(rem_port_hex, 16), state, proto)
        except (ValueError, OSError):
            continue


class NetstatCollector(BaseCollector):
    def __init__(self, agent_id, hostname, interval=60):
        super().__init__(agent_id, hostname)
        self.interval = interval
        self._next_run = 0.0
        self._seen = set()  # (proto, src_ip, src_port, dst_ip, dst_port)

    def _current_outbound(self):
        conns = {}
        tables = [
            ("/proc/net/tcp", "tcp", _decode_ipv4),
            ("/proc/net/tcp6", "tcp6", _decode_ipv6),
        ]
        for path, proto, decoder in tables:
            if not os.path.exists(path):
                continue
            for local_ip, local_port, rem_ip, rem_port, state, _p in _parse_table(
                    path, proto, decoder):
                if state not in (_ST_ESTABLISHED, _ST_SYN_SENT):
                    continue
                if rem_ip in ("0.0.0.0", "::"):
                    continue  # listener, not a connection
                if _is_loopback(rem_ip):
                    continue  # skip loopback noise
                if local_port < _EPHEMERAL_MIN:
                    continue  # server-side socket -> treat as inbound, skip
                key = (proto, local_ip, local_port, rem_ip, rem_port)
                conns[key] = {
                    "proto": proto, "src_ip": local_ip, "src_port": local_port,
                    "dst_ip": rem_ip, "dst_port": rem_port,
                    "direction": "outbound", "action": "allowed",
                }
        return conns

    def collect(self, snapshot=False):
        now = time.monotonic()
        if not snapshot and now < self._next_run:
            return []
        self._next_run = now + self.interval

        current = self._current_outbound()

        if not self._seen and not snapshot:
            self._seen = set(current)  # baseline silently on first run
            log.info("network baseline established (%d outbound connections)",
                     len(current))
            return []

        events = []
        for key, info in current.items():
            if key not in self._seen:
                raw = "%s %s:%d -> %s:%d outbound" % (
                    info["proto"], info["src_ip"], info["src_port"],
                    info["dst_ip"], info["dst_port"])
                events.append(self.make_event("network", dict(info), raw=raw))

        if len(events) > _MAX_EVENTS_PER_CYCLE:
            log.warning("network scan found %d new connections; capping at %d",
                        len(events), _MAX_EVENTS_PER_CYCLE)
            events = events[:_MAX_EVENTS_PER_CYCLE]

        self._seen = set(current)  # drop closed connections from tracking
        return events
