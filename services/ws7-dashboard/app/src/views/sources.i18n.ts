// Strings for the Sources / onboarding view. Every claim here is backed by the repo
// (WS-1 UDP listener, WS-2 parser routing, WS-6 MAC-keyed inventory); see Sources.tsx.

const en = {
  types: "source types",
  flowLabel: "How it flows",
  flow: ["Device", "WS-1 (UDP 5514 or JSONL shipper)", "WS-2 parser", "WS-4 detection", "Alarms"],
  flowNote: "Inventory is fed separately: only MAC-bearing asset observations (today the bundled SNMP mock) or a POST /assets/upsert to the inventory API add a device there.",

  connect: "Connect a device",
  step1: "Pick the device type",
  step1Hint: "Only types with a working input path and a shipped parser are listed.",
  deviceType: "Device type",
  step2: "Configure the device",
  hostLabel: "Collector address (this FENGARDE host)",
  copy: "Copy",
  copied: "Copied to the clipboard.",
  copyManual: "The clipboard is blocked here. The text is selected: press Ctrl+C.",
  shipperNote: "If REDIS_PASSWORD is set, use redis://:PASSWORD@127.0.0.1:6379/0.",
  arrivesAs: "Arrives as source type",
  orRouted: "or, when the line looks like one of these, as",
  step3: "Wait for the first event",
  wantLabel: "Device hostname or IP (optional, narrows the check)",
  pickFirst: "Pick a device type first.",
  notLoaded: "Events are not loaded yet, so the check cannot start.",
  waiting: (st: string) => `Waiting for a new ${st} event. The console re-reads every 10 s.`,
  lastCheck: "Last check",
  already: (n: number) => `${n} earlier matching events are already in range; only a new one counts.`,
  received: "First event received",
  from: "from",
  invNote: "The device will not appear in Inventory on its own: Inventory is keyed by MAC address, and syslog or JSON log lines carry none. Inventory learns devices only from MAC-bearing asset observations (today the bundled SNMP mock) or a POST /assets/upsert to the inventory API.",
  invLink: "Open Inventory",

  devices: {
    rsyslog: {
      name: "Linux (rsyslog)",
      note: "A single @ forwards over UDP in rsyslog's default traditional (RFC 3164) format, which the generic_syslog parser reads.",
    },
    syslogng: {
      name: "Linux (syslog-ng)",
      note: "network() sends the legacy BSD (RFC 3164) format. Do not use the syslog() driver: it sends RFC 5424, which is not parsed. s_src is the Debian/Ubuntu source name; use your distribution's.",
    },
    k8s: {
      name: "Kubernetes audit log",
      note: "Needs API-server auditing switched on (--audit-policy-file, --audit-log-path). Run from the FENGARDE repo checkout on the FENGARDE host, where the bus (Redis) listens on 127.0.0.1. Needs Python with the redis package.",
    },
    cloudtrail: {
      name: "AWS CloudTrail",
      note: "No S3 or CloudWatch puller ships. This is a one-shot import per downloaded CloudTrail file: jq turns its Records array into one JSON object per line. Run on the FENGARDE host from the repo checkout.",
    },
    windows: {
      name: "Windows Event Log",
      note: "FENGARDE ships no Windows agent or forwarder. You have to export events yourself as one flat JSON object per line (EventID, TimeCreated, Computer, ...). Run on the FENGARDE host from the repo checkout.",
    },
    mcp: {
      name: "AI agent / MCP server",
      note: "Tails a JSONL tool-call log, see docs/agent-monitoring.md. Run on the FENGARDE host from the repo checkout.",
    },
  },

  health: "WS-1 ingest health",
  noMetrics: "No metrics: the WS-1 /metrics endpoint did not answer",
  noListener: "WS-1 answered but reports no UDP listener counters: the listener did not bind (port in use or missing permission). Check the ws1-collectors logs.",
  healthNote: "UDP listener only. Events from the JSONL shipper go straight onto the bus and are not counted here.",
  counters: {
    events_produced: "Produced to raw.events",
    events_dropped: "Dropped (bus write failed)",
    events_shed: "Shed (rate limit)",
    events_spooled: "Spooled to disk",
    events_lost: "Lost (spool full)",
    events_queue_full: "Refused (worker queue full)",
    events_empty: "Empty datagrams",
    recv_oserror_total: "Receive errors",
    udp_rcvbuf_errors_cumulative: "Kernel receive-buffer drops",
  },
  silence: "Last datagram",
  silenceNote: "Measured from listener start while nothing has arrived yet.",
  perSender: "Per sender (peer IP)",
  produced: "Produced",
  dropped: "Dropped",
  shed: "Shed",
  empty: "Empty",
  noSenders: "No datagram has reached the listener yet.",

  events: "Events",
  topSenders: "Top senders",
  tableHint: "Counted over the events this console loaded for the selected time range.",

  limits: "Not connectable today",
  limitItems: [
    "Cisco ASA, sshd and CEF lines sent over UDP do not reach their own parsers: WS-1 stamps every datagram source_type=generic_syslog and WS-2 treats that as authoritative, so cisco_asa, linux_ssh and cef (and the rules built on them, such as SSH brute force) never see UDP traffic. Lines without an RFC 3164 header, such as default ASA or IOS output, are dead-lettered.",
    "RFC 5424 senders (syslog-ng syslog() driver, rsyslog RFC 5424 templates): generic_syslog reads RFC 3164 headers only; other lines are dead-lettered.",
    "Syslog over TCP or TLS is not implemented; the listener is UDP only.",
    "SNMP and NetFlow: WS-1 reads bundled mock files only; live polling and flow receivers are not wired.",
    "The UDP listener is unauthenticated: keep it on a trusted segment or behind a VPN.",
  ],
};

const de: typeof en = {
  types: "Quelltypen",
  flowLabel: "So fließen die Daten",
  flow: ["Gerät", "WS-1 (UDP 5514 oder JSONL-Shipper)", "WS-2-Parser", "WS-4-Erkennung", "Alarme"],
  flowNote: "Das Inventar wird getrennt befüllt: Nur Asset-Beobachtungen mit MAC-Adresse (derzeit der mitgelieferte SNMP-Mock) oder ein POST /assets/upsert an die Inventar-API legen dort ein Gerät an.",

  connect: "Gerät anbinden",
  step1: "Gerätetyp wählen",
  step1Hint: "Aufgeführt sind nur Typen mit funktionierendem Eingang und mitgeliefertem Parser.",
  deviceType: "Gerätetyp",
  step2: "Gerät konfigurieren",
  hostLabel: "Collector-Adresse (dieser FENGARDE-Host)",
  copy: "Kopieren",
  copied: "In die Zwischenablage kopiert.",
  copyManual: "Die Zwischenablage ist hier gesperrt. Der Text ist markiert: Strg+C drücken.",
  shipperNote: "Ist REDIS_PASSWORD gesetzt, redis://:PASSWORT@127.0.0.1:6379/0 verwenden.",
  arrivesAs: "Kommt an als Quelltyp",
  orRouted: "oder, wenn die Zeile wie eine davon aussieht, als",
  step3: "Auf das erste Ereignis warten",
  wantLabel: "Hostname oder IP des Geräts (optional, grenzt die Prüfung ein)",
  pickFirst: "Zuerst einen Gerätetyp wählen.",
  notLoaded: "Ereignisse sind noch nicht geladen, die Prüfung kann nicht starten.",
  waiting: (st: string) => `Warte auf ein neues ${st}-Ereignis. Die Konsole liest alle 10 s neu.`,
  lastCheck: "Zuletzt geprüft",
  already: (n: number) => `${n} frühere passende Ereignisse liegen bereits im Zeitraum; nur ein neues zählt.`,
  received: "Erstes Ereignis empfangen",
  from: "von",
  invNote: "Das Gerät erscheint nicht von selbst im Inventar: Das Inventar ist nach MAC-Adresse geschlüsselt, und Syslog- oder JSON-Logzeilen enthalten keine. Das Inventar lernt Geräte nur aus Asset-Beobachtungen mit MAC-Adresse (derzeit der mitgelieferte SNMP-Mock) oder über ein POST /assets/upsert an die Inventar-API.",
  invLink: "Inventar öffnen",

  devices: {
    rsyslog: {
      name: "Linux (rsyslog)",
      note: "Ein einzelnes @ leitet per UDP im traditionellen Standardformat von rsyslog (RFC 3164) weiter, das der Parser generic_syslog liest.",
    },
    syslogng: {
      name: "Linux (syslog-ng)",
      note: "network() sendet das klassische BSD-Format (RFC 3164). Nicht den Treiber syslog() verwenden: Er sendet RFC 5424, das nicht geparst wird. s_src ist der Quellname unter Debian/Ubuntu; den der eigenen Distribution einsetzen.",
    },
    k8s: {
      name: "Kubernetes-Audit-Log",
      note: "Setzt eingeschaltetes Auditing am API-Server voraus (--audit-policy-file, --audit-log-path). Aus dem FENGARDE-Repo auf dem FENGARDE-Host ausführen, dort lauscht der Bus (Redis) auf 127.0.0.1. Benötigt Python mit dem Paket redis.",
    },
    cloudtrail: {
      name: "AWS CloudTrail",
      note: "Ein S3- oder CloudWatch-Abruf wird nicht mitgeliefert. Dies ist ein einmaliger Import je heruntergeladener CloudTrail-Datei: jq macht aus dem Records-Array ein JSON-Objekt pro Zeile. Auf dem FENGARDE-Host aus dem Repo ausführen.",
    },
    windows: {
      name: "Windows-Ereignisprotokoll",
      note: "FENGARDE liefert keinen Windows-Agenten und keinen Forwarder mit. Ereignisse müssen selbst als flaches JSON-Objekt pro Zeile exportiert werden (EventID, TimeCreated, Computer, ...). Auf dem FENGARDE-Host aus dem Repo ausführen.",
    },
    mcp: {
      name: "KI-Agent / MCP-Server",
      note: "Liest ein JSONL-Protokoll der Tool-Aufrufe fortlaufend mit, siehe docs/agent-monitoring.md. Auf dem FENGARDE-Host aus dem Repo ausführen.",
    },
  },

  health: "WS-1-Eingangszustand",
  noMetrics: "Keine Metriken: Der /metrics-Endpunkt von WS-1 hat nicht geantwortet",
  noListener: "WS-1 antwortet, meldet aber keine Zähler des UDP-Listeners: Der Listener konnte nicht binden (Port belegt oder fehlende Berechtigung). Logs von ws1-collectors prüfen.",
  healthNote: "Nur der UDP-Listener. Ereignisse vom JSONL-Shipper gehen direkt auf den Bus und werden hier nicht gezählt.",
  counters: {
    events_produced: "An raw.events übergeben",
    events_dropped: "Verworfen (Bus-Schreiben fehlgeschlagen)",
    events_shed: "Abgeworfen (Ratenlimit)",
    events_spooled: "Auf Platte gepuffert",
    events_lost: "Verloren (Puffer voll)",
    events_queue_full: "Abgewiesen (Worker-Warteschlange voll)",
    events_empty: "Leere Datagramme",
    recv_oserror_total: "Empfangsfehler",
    udp_rcvbuf_errors_cumulative: "Verluste im Kernel-Empfangspuffer",
  },
  silence: "Letztes Datagramm",
  silenceNote: "Gemessen ab Start des Listeners, solange noch nichts angekommen ist.",
  perSender: "Je Absender (Peer-IP)",
  produced: "Übergeben",
  dropped: "Verworfen",
  shed: "Abgeworfen",
  empty: "Leer",
  noSenders: "Bisher hat kein Datagramm den Listener erreicht.",

  events: "Ereignisse",
  topSenders: "Häufigste Absender",
  tableHint: "Gezählt über die Ereignisse, die diese Konsole für den gewählten Zeitraum geladen hat.",

  limits: "Derzeit nicht anbindbar",
  limitItems: [
    "Cisco-ASA-, sshd- und CEF-Zeilen per UDP erreichen ihre eigenen Parser nicht: WS-1 versieht jedes Datagramm mit source_type=generic_syslog, und WS-2 behandelt das als verbindlich. cisco_asa, linux_ssh und cef (und die darauf aufbauenden Regeln, etwa SSH-Brute-Force) sehen UDP-Verkehr daher nie. Zeilen ohne RFC-3164-Kopf, etwa die Standardausgabe von ASA oder IOS, landen in der Dead-Letter-Queue.",
    "Absender mit RFC 5424 (syslog-ng-Treiber syslog(), rsyslog-Vorlagen für RFC 5424): generic_syslog liest nur RFC-3164-Köpfe; andere Zeilen landen in der Dead-Letter-Queue.",
    "Syslog über TCP oder TLS ist nicht implementiert; der Listener spricht nur UDP.",
    "SNMP und NetFlow: WS-1 liest nur mitgelieferte Mock-Dateien; echtes Polling und Flow-Empfang sind nicht angebunden.",
    "Der UDP-Listener ist nicht authentifiziert: Nur in einem vertrauenswürdigen Segment oder hinter einem VPN betreiben.",
  ],
};

export const S = { en, de };
