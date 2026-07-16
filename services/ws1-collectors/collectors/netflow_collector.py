"""NetFlow / IPFIX collector.

Receives flow records exported by routers/switches (NetFlow v5/v9, IPFIX) and
emits one raw payload per flow. Decoding the binary NetFlow/IPFIX wire format
requires template state and is out of scope for this skeleton; instead the
collector consumes already-decoded flow records from a mock JSON source. The
record shape mirrors the common IPFIX information elements (src/dst addr+port,
protocol, byte/packet counts).

The partition key for ``raw.events`` is the flow's source IP (the host that
originated the traffic), matching Contract B's ``src_endpoint.ip``.

NetFlow has no hostname/MAC, so this collector does NOT emit ``assets.updates``
observations — but the interface method exists (returning nothing) so all
collectors are uniform.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterator, Optional

from shared.envelope import stamp_meta


class NetflowCollector:
    """Pluggable NetFlow/IPFIX collector backed by a mock flow file."""

    SOURCE_TYPE = "netflow_ipfix"

    def __init__(self, flows_file: Optional[str] = None, flows: Optional[list] = None):
        """:param flows_file: path to a JSON file with a ``flows`` list.
        :param flows: in-memory flow list (overrides ``flows_file``).
        """
        if flows is not None:
            self._flows = flows
        elif flows_file is not None:
            data = json.loads(Path(flows_file).read_text(encoding="utf-8"))
            self._flows = data.get("flows", [])
        else:
            self._flows = []

    def poll(self) -> Iterator[dict]:
        """Yield one raw payload per flow record."""
        for flow in self._flows:
            payload = self._handle_flow(flow)
            if payload is not None:
                yield payload

    def _handle_flow(self, flow: dict) -> Optional[dict]:
        # IPFIX sourceIPv4Address; fall back through common key spellings.
        src_ip = (
            flow.get("src_ip")
            or flow.get("sourceIPv4Address")
            or "0.0.0.0"
        )
        received_at = int(time.time())

        meta = {
            "ip": src_ip,
            "received_at": received_at,
            "exporter": flow.get("exporter"),
            "protocol": flow.get("protocol"),
            "version": flow.get("version", "ipfix"),
        }

        return {
            "source_type": self.SOURCE_TYPE,
            "raw": json.dumps(flow, sort_keys=True),
            "meta": stamp_meta(meta),
        }

    def asset_observations(self) -> Iterator[dict]:
        """NetFlow carries no asset identity — yields nothing. Uniform interface."""
        return iter(())
