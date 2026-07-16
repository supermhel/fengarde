"""SNMP polling collector.

Polls SNMP-capable devices (switches, routers, firewalls) and emits one raw
payload per device per poll cycle. Real SNMP I/O (pysnmp / net-snmp) is out of
scope for this skeleton and would require network access, so the collector reads
device responses from a mock source: a JSON file describing each device's polled
OIDs. The shape of the mock mirrors what an SNMP GET/WALK would return.

SNMP is a rich source of asset inventory data: sysName (hostname), interface
MAC addresses (ifPhysAddress) and management IP all come from standard MIBs, so
this collector emits ``assets.updates`` observations with mac+ip+hostname.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterator, Optional

from shared.envelope import stamp_meta

# Standard MIB OIDs we care about for asset discovery.
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"          # sysName.0  -> hostname
OID_IFPHYSADDRESS = "1.3.6.1.2.1.2.2.1.6"  # ifPhysAddress -> MAC


class SnmpCollector:
    """Pluggable SNMP polling collector backed by a mock device file."""

    SOURCE_TYPE = "snmp"

    def __init__(self, devices_file: Optional[str] = None, devices: Optional[list] = None):
        """:param devices_file: path to a JSON file with a ``devices`` list.
        :param devices: in-memory device list (overrides ``devices_file``).
        """
        if devices is not None:
            self._devices = devices
        elif devices_file is not None:
            data = json.loads(Path(devices_file).read_text(encoding="utf-8"))
            self._devices = data.get("devices", [])
        else:
            self._devices = []
        self._assets: list[dict] = []

    def poll(self) -> Iterator[dict]:
        """Poll every configured device, yielding one raw payload each."""
        for device in self._devices:
            payload = self._poll_device(device)
            if payload is not None:
                yield payload

    def _poll_device(self, device: dict) -> Optional[dict]:
        ip = device.get("ip") or "0.0.0.0"
        oids = device.get("oids", {})
        polled_at = int(time.time())

        hostname = oids.get(OID_SYSNAME) or device.get("hostname")
        mac = oids.get(OID_IFPHYSADDRESS) or device.get("mac")

        meta = {
            "ip": ip,
            "polled_at": polled_at,
            "community": device.get("community", "public"),
            "hostname": hostname,
        }

        # Asset observation: SNMP gives us all three of mac/ip/hostname.
        if ip != "0.0.0.0" and (mac or hostname):
            self._assets.append(
                {
                    "mac": mac,
                    "ip": ip,
                    "hostname": hostname,
                    "seen_at": polled_at,
                }
            )

        # raw is the device's polled OID map, serialized — WS-2 normalizes it.
        return {
            "source_type": self.SOURCE_TYPE,
            "raw": json.dumps({"ip": ip, "oids": oids}, sort_keys=True),
            "meta": stamp_meta(meta),
        }

    def asset_observations(self) -> Iterator[dict]:
        """Drain discovered ``assets.updates`` observations (mac/ip/hostname/seen_at)."""
        while self._assets:
            yield self._assets.pop(0)
