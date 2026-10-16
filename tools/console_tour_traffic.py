"""Lab traffic for the console tour (screenshots and video on the Pages site).

Sends a two-stage attack from ONE source IP to WS-1's UDP syslog listener, exactly as a Linux host
and a DNS resolver forwarding their logs would, plus a little firewall noise:

  1. sshd "Failed password" x12      -> rule: authentication brute-force      (MITRE TA0006)
  2. dnsmasq query[A] x48 distinct   -> rule: DNS volume to many domains      (MITRE TA0011)
  3. Cisco ASA deny x4, CEF x2       -> extra sources for the Sources / Events views

WS-8 joins the two alarms on the shared source IP into one incident. The traffic is generated here and
sent to your own stack: it is lab data, not a recording of a real attack.

Usage: python tools/console_tour_traffic.py [host] [port] [attacker_ip]
Defaults: 127.0.0.1 5514 203.0.113.77 (RFC 5737 documentation range).
The UDP listener is unauthenticated: only point this at a stack you own.
"""
from __future__ import annotations

import socket
import sys
import time

host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 5514
attacker = sys.argv[3] if len(sys.argv) > 3 else "203.0.113.77"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def stamp() -> str:
    return time.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1)


def send(line: str, pause: float = 0.04) -> None:
    sock.sendto(line.encode(), (host, port))
    time.sleep(pause)


for i in range(12):
    user = ["root", "admin", "oracle", "ubuntu"][i % 4]
    send(f"<38>{stamp()} web-01 sshd[{4100 + i}]: Failed password for invalid user {user} from {attacker} port {50000 + i} ssh2")

for i in range(48):  # 40 distinct names inside 60 s trips the rule
    send(f"<30>{stamp()} dns-01 dnsmasq[212]: query[A] x{i:02d}.t{i * 7919 % 9973}.exfil-lab.example from {attacker}")

for i in range(4):
    send(f"<164>{stamp()} fw-01 : %ASA-4-106023: Deny tcp src outside:198.51.100.{20 + i}/5{i}000 "
         f"dst inside:10.0.0.{10 + i}/22 by access-group acl_out")
for i in range(2):
    send(f"<134>{stamp()} relay-01 CEF:0|Acme|Firewall|1.0|100|Failed login|7|"
         f"src=198.51.100.{60 + i} suser=svc-backup outcome=failure")

print(f"sent: 12 sshd + 48 DNS from {attacker}, 4 ASA, 2 CEF -> {host}:{port}")
