"""plc_sim -- a deterministic, loopback-only simulated PLC for FENGARDE eval.

WP-1-A (Phase-1 dependency root). This is a *simulated* programmable logic
controller: a small, explicit tank/pump process model exposed through a
Modbus/TCP server, plus a socket-free tick model a caller can drive directly.

PURPOSE
    FENGARDE's future AI-to-OT detection claim needs a number behind it.
    This module gives the eval harness a deterministic twin of a real PLC:
    the same seed produces the identical byte-for-byte trace every run, so a
    "detector" can be scored against a reproducible process.

SAFETY CONSTRAINT (non-negotiable, stated AND enforced)
    * The Modbus/TCP listener binds LOOPBACK ONLY -- hard-coded 127.0.0.1,
      never INADDR_ANY, enforced in code by `ModbusServer._bind_host()`
      raising if anything other than the loopback address is requested.
    * This sim never issues a real control action. The only values that ever
      change a register are internal to this process (the seeded tick loop
      and inbound reads/writes on the loopback socket). FENGARDE -- at every
      layer, including any future AI triage/detection model -- NEVER decides
      or issues a real PLC action. Detection output is advisory only; it is
      never wired back into this sim or into any physical controller.
    * Isolated by design: no OCSF, no detection logic, no WS rules, no
      network egress. Everything lives on the loopback interface.

LIBRARY ENTRY POINT
    from eval.twin.plc_sim import PLCSim, simulate
    sim = PLCSim(seed=1)          # no socket touched
    sim.step(100)                 # advance ticks without binding a server
    sim.holding(REG_LEVEL)        # read the current level

    The Modbus/TCP server is a separate, opt-in mode for exposing the same
    registers to a protocol client; it is not needed to drive the tick model.

STANDARDS
    Modbus Application Protocol V1.1b3 (public, modbus.org). Only the small
    subset needed to expose registers/coils on loopback is implemented:
    FC 1 (read coils), FC 3 (read holding registers), FC 5 (write single
    coil), FC 6 (write single register). STDLIB ONLY (socket + struct).

Determinism: random.Random(seed) is the single source of randomness; the
trace is a list of plain integers printed in fixed column order (never a
dict ordering hazard). No wall-clock, no timestamps.
"""

from __future__ import annotations

import argparse
import struct
from random import Random
from socket import AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, socket

# --------------------------------------------------------------------------
# Process-model register/coil map (Modbus data model, 16-bit unsigned words).
# --------------------------------------------------------------------------
REG_SETPOINT = 0        # holding register: target tank level (operator setpoint)
REG_LEVEL = 1           # holding register: current tank level
REG_PUMP_STATE = 2      # holding register: 1 = pump running, 0 = stopped
COIL_PUMP_ENABLE = 0    # coil: 1 = enable pump, 0 = disable

_NUM_HOLDING = 3        # holding registers exposed
_NUM_COILS = 1          # coils exposed

# Scale: level & setpoint are integer basis points of tank capacity (0..1000,
# 1000 == full). Modbus registers are unsigned 16-bit, so this fits comfortably.
_TANK_SCALE = 1000
_FILL_RATE = 18          # basis points gained per tick while the pump runs
_DRAIN_RATE = 9          # basis points lost per tick while the pump is stopped
_NOISE_AMPLITUDE = 4     # +-per-tick process disturbance, seeded


def _clamp0(value: int) -> int:
    """Clamp a value into a non-negative integer (tank floor + uint16 safe)."""
    if value < 0:
        return 0
    return value


class PLCSim:
    """The socket-free process twin: ownership of state lives here.

    A caller (the future scenario module) constructs a PLCSim, advances ticks
    with `step()`/`tick()`, and reads/writes the register/coil map directly.
    No socket is ever opened by this class; the Modbus server is separate.
    """

    def __init__(self, seed: int) -> None:
        self.seed = int(seed)
        self._rng = Random(self.seed)          # ONLY randomness; exact per seed.
        self._tick_no = 0
        # Initial process state, seeded so different seeds start differently.
        setpoint = self._rng.randint(int(0.50 * _TANK_SCALE), int(0.95 * _TANK_SCALE))
        level = self._rng.randint(0, int(0.30 * _TANK_SCALE))
        self._holding: list[int] = [setpoint, level, 0]  # [setpoint, level, pump_state]
        self._coils: list[int] = [0] * _NUM_COILS        # pump-enable coil, starts off

    # -- read/write accessors over the Modbus data model --------------------
    def read_holding(self, addr: int) -> int:
        """Read one holding register (Modbus FC3 payload value)."""
        return self._holding[addr]

    def read_coil(self, addr: int) -> int:
        """Read one coil as 0/1 (Modbus FC1 payload value)."""
        return self._coils[addr]

    def write_holding(self, addr: int, value: int) -> None:
        """Write a holding register (Modbus FC6), coerced to uint16 range."""
        self._holding[addr] = struct.unpack(">H", struct.pack(">H", int(value)))[0]

    def write_coil(self, addr: int, value: bool) -> None:
        """Write one coil (Modbus FC5). on => 1, else 0."""
        self._coils[addr] = 1 if value else 0

    # -- process integration ------------------------------------------------
    def tick(self) -> tuple[int, int, int, int]:
        """Advance the process by one tick; return the post-tick snapshot.

        Physics: if the pump-enable coil is on, the pump runs and the tank
        level rises toward the setpoint (clamped there); if it is off, the
        tank drains toward empty (clamped at zero). A small seeded +-noise
        per tick keeps distinct seeds from colliding. Returns
        (tick_index, setpoint, level, pump_enable).
        """
        enable = self._coils[COIL_PUMP_ENABLE] != 0
        self._holding[REG_PUMP_STATE] = 1 if enable else 0

        level = self._holding[REG_LEVEL]
        setpoint = self._holding[REG_SETPOINT]
        noise = self._rng.randint(-_NOISE_AMPLITUDE, _NOISE_AMPLITUDE)

        if enable:
            level += _FILL_RATE + noise
            if level > setpoint:
                level = setpoint                # tank reached the target
        else:
            level -= _DRAIN_RATE - noise
            level = _clamp0(level)              # tank drains toward empty

        self._holding[REG_LEVEL] = _clamp0(level)
        self._tick_no += 1
        return self.snapshot()

    def step(self, ticks: int) -> list[tuple[int, int, int, int]]:
        """Advance `ticks` ticks and return every snapshot, in order."""
        return [self.tick() for _ in range(int(ticks))]

    def snapshot(self) -> tuple[int, int, int, int]:
        """(tick_index, setpoint, level, pump_enable) of the live state."""
        return (
            self._tick_no,
            self._holding[REG_SETPOINT],
            self._holding[REG_LEVEL],
            self._coils[COIL_PUMP_ENABLE],
        )


def simulate(seed: int, ticks: int) -> list[tuple[int, int, int, int]]:
    """Top-level library helper: run `ticks` ticks, return the trace.

    Each trace element is (tick_index, setpoint, level, pump_enable) -- a
    plain tuple of ints, printed in this exact fixed column order so output
    is byte-stable for a given seed.
    """
    return PLCSim(seed=seed).step(ticks)


# --------------------------------------------------------------------------
# Loopback-only Modbus/TCP server (opt-in; not needed for the tick model).
# --------------------------------------------------------------------------
_LOOPBACK_BIND = "127.0.0.1"      # SAFETY: loopback only, never INADDR_ANY.
_FC_READ_COILS = 1
_FC_READ_HOLDING = 3
_FC_WRITE_SINGLE_COIL = 5
_FC_WRITE_SINGLE_REGISTER = 6


class ModbusServer:
    """Minimal Modbus/TCP server bound to LOOPBACK ONLY, wrapping a PLCSim.

    SAFETY: the bind host is hard-coded to 127.0.0.1; there is no code path
    that binds INADDR_ANY. `_bind_host()` raises if anything else is passed,
    so even a mistaken caller cannot open the sim to the network. This sim
    never issues a real control action -- writes only mutate the in-memory
    registers of this throwaway process twin.
    """

    def __init__(self, sim: PLCSim, port: int = 15020) -> None:
        self.sim = sim
        self.port = int(port)

    @staticmethod
    def _bind_host(host: str) -> str:
        """SAFETY enforcement: only the loopback address may be bound."""
        if host != _LOOPBACK_BIND:
            raise ValueError(
                "refusing to bind non-loopback host %r; the sim is "
                "loopback-only by design (FENGARDE never issues a real "
                "PLC action)" % (host,)
            )
        return host

    def serve(self) -> None:
        """Bind loopback, accept one connection at a time, answer requests.

        Blocks until the listening socket is closed. The bound address is
        always 127.0.0.1 (see `_bind_host`).
        """
        host = self._bind_host(_LOOPBACK_BIND)      # enforced loopback
        with socket(AF_INET, SOCK_STREAM) as sock:
            sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            sock.bind((host, self.port))
            sock.listen(1)
            while True:
                conn, _addr = sock.accept()
                with conn:
                    self._handle(conn)

    # -- frame handling -----------------------------------------------------
    @staticmethod
    def _read_exact(conn: socket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = conn.recv(n - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf

    def _handle(self, conn: socket) -> None:
        """Read MBA/TCP frames and dispatch the supported function codes."""
        while True:
            header = self._read_exact(conn, 7)
            if len(header) < 7:
                return
            _tx, _proto, length, _unit = struct.unpack(">HHHB", header)
            pdu = self._read_exact(conn, length - 1)   # length includes unit id
            if len(pdu) < 1:
                return
            fc, data = pdu[0], pdu[1:]
            resp = self._dispatch(fc, data)
            if resp is None:
                resp = struct.pack(">B", fc | 0x80) + b"\x01"   # illegal function
            mbap = struct.pack(">HHHB", _tx, 0, len(resp) + 1, _unit)
            conn.sendall(mbap + resp)

    def _dispatch(self, fc: int, data: bytes) -> bytes | None:
        """Return the response PDU (after the function code) or None if unsupported."""
        if fc == _FC_READ_COILS:
            addr = struct.unpack(">H", data[0:2])[0]
            count = struct.unpack(">H", data[2:4])[0]
            bytecount = (count + 7) // 8
            out = bytearray(bytecount)
            for i in range(count):
                if self.sim.read_coil(addr + i):
                    out[i // 8] |= 1 << (i % 8)
            return struct.pack(">B", bytecount) + bytes(out)
        if fc == _FC_READ_HOLDING:
            addr = struct.unpack(">H", data[0:2])[0]
            count = struct.unpack(">H", data[2:4])[0]
            regs = b"".join(struct.pack(">H", self.sim.read_holding(addr + i))
                            for i in range(count))
            return struct.pack(">B", len(regs)) + regs
        if fc == _FC_WRITE_SINGLE_COIL:
            addr = struct.unpack(">H", data[0:2])[0]
            value = struct.unpack(">H", data[2:4])[0]
            self.sim.write_coil(addr, value == 0xFF00)
            return struct.pack(">HH", addr, value)
        if fc == _FC_WRITE_SINGLE_REGISTER:
            addr = struct.unpack(">H", data[0:2])[0]
            value = struct.unpack(">H", data[2:4])[0]
            self.sim.write_holding(addr, value)
            return struct.pack(">HH", addr, value)
        return None


def _print_trace(trace) -> None:
    """Print a byte-stable, human-readable trace (fixed column order)."""
    print("# FENGARDE simulated PLC trace (deterministic)")
    print("# columns: tick,setpoint,level,pump_enable")
    for tick, setpoint, level, enable in trace:
        print(f"{tick},{setpoint},{level},{enable}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="plc_sim",
        description="Deterministic loopback-only simulated PLC (WP-1-A).",
    )
    parser.add_argument("--seed", type=int, default=1,
                        help="RNG seed (same seed => byte-identical trace)")
    parser.add_argument("--ticks", type=int, default=100,
                        help="number of process ticks to simulate")
    parser.add_argument("--serve", action="store_true",
                        help="run the loopback-only Modbus/TCP server instead")
    parser.add_argument("--port", type=int, default=15020,
                        help="loopback server port (default 15020)")
    args = parser.parse_args(argv)

    sim = PLCSim(seed=args.seed)
    if args.serve:
        ModbusServer(sim, port=args.port).serve()
        return 0
    _print_trace(sim.step(args.ticks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
