# AVGuard Security Suite Roadmap

The owner's six-phase plan for where AVGuard goes, written 4 October 2026,
kept here beside the measured ROADMAP.md so the two can be read together.
ROADMAP.md records what was built and what it measured; this records what
the whole suite is meant to become and in what order. The mapping at the
end says where this repository stands on each phase.

## The vision

AVGuard grows from a file scanner into a home security suite: a Python
brain, a Rust sensor, C++ network tools and an ESP32 robot that guards the
antivirus itself. The design rule throughout: the AI advises, you approve,
and hardware enforces. Phases 1 and 2 are small and independent; from
phase 3 on, each phase feeds the next, which is why the AI supervisor
comes last.

## Ground rules

- One build at a time. The next phase starts only when the current one is
  on GitHub with a README and a demo.
- Every phase works on its own. If you stop halfway through the roadmap,
  you still have finished pieces to show.
- Only scan and sniff networks you own. Home network yes, school or café
  Wi-Fi no. Unauthorized scanning can fall under Thailand's Computer Crime
  Act.
- AI advises, human approves, hardware enforces. The AI never deletes,
  restores or disables anything on its own.

Each language has one job:

| Part | Language | Job |
|---|---|---|
| AVGuard core | Python | Detection logic, YARA, quarantine, AI supervisor |
| Sensor | Rust | Fast, always-on process and network monitoring |
| Linux tools | C++ | Ping, sweep, traceroute: learning packets from the ground up |
| Robot | ESP32 (Arduino C++) | Alarm, face, approval buttons |

## Phase 1: C++ ping on Linux

A working ping you wrote yourself, built on raw ICMP. It comes first
because it fits the C++ lessons already running. You learn: ICMP, sockets,
how bytes sit inside a packet, and why raw sockets need root. Done when
your ping matches the system ping on the same host and handles a host
that is down.

Steps: an internet checksum function, tested on its own; build an ICMP
Echo Request (type 8, code 0, id, sequence, payload); open the socket
(SOCK_RAW as root, then try unprivileged SOCK_DGRAM); resolve a hostname
with getaddrinfo(); send with sendto(), receive with recvfrom(), match
replies by id and sequence; skip the IP header on raw replies (IHL x 4
bytes); measure RTT with std::chrono::steady_clock; a timeout with
SO_RCVTIMEO so a dead host does not hang the program; a summary line of
sent, received, loss and min/avg/max RTT.

Follow-ups: a ping sweep of the home subnet (host discovery for the
Network Watchdog); traceroute by sending TTL 1, 2, 3 and so on; a TTL hint
for the remote OS (Linux often 64, Windows 128).

## Phase 2: ESP32 heartbeat tamper alarm

A separate device that screams when AVGuard goes silent. Malware that
kills AVGuard cannot silence a board it does not control. You learn:
microcontroller basics, serial communication, timeouts, out-of-band
monitoring. Done when you kill the AVGuard process in Task Manager and the
alarm fires within the timeout.

Steps: the board arrives, install the USB driver, confirm the PC sees it
(a data cable!); blink an LED; read text sent from the PC over USB serial;
AVGuard sends a heartbeat message every few seconds; the ESP32 tracks the
time since the last heartbeat; green LED while heartbeats arrive, red LED
plus buzzer when they stop; a button to acknowledge and silence the alarm.

## Phase 3: Rust sensor

A fast, always-on Rust program that watches processes and their network
connections, then hands events to AVGuard. AVGuard's Python code stays;
Rust only becomes its eyes. You learn: Rust ownership and borrowing,
Windows internals, event-driven monitoring with ETW. Done when a process
that starts and exits in under a second shows up through ETW, where
polling missed it.

Steps: Rust basics (ownership, borrowing, Result error handling); list
running processes with sysinfo; show which process owns which connection
with netstat2; turn each event into JSON with serde_json; send events to
Python over a named pipe or local socket; AVGuard reads and logs the
events; switch from polling to ETW with ferrisetw; later, for the Network
Watchdog, full packet capture with Npcap and the pcap crate.

## Phase 4: Detection features

The features that make AVGuard different from a smaller Defender. Each one
is small enough to ship on its own. You learn: behaviour-based detection,
baselining, and how to measure false positives. Done when each feature has
a test case that triggers it and a check that normal use does not.

- Beaconing detection: flag connections that repeat on a near-perfect
  timer (malware phoning home).
- New destination baseline: learn which programs normally talk to which
  IPs, flag the first-time ones.
- Threat intel lookup: check destinations against a public blocklist such
  as abuse.ch.
- ClickFix guard: warn when the clipboard holds an encoded PowerShell or
  mshta command.
- Crypto clipboard swap: catch a wallet address silently replaced by
  another.
- Persistence diff: a daily snapshot of autoruns, scheduled tasks,
  services and Run keys; show only what is new.

## Phase 5: Robot control panel

The ESP32 grows from an alarm into AVGuard's body: a face, lights and real
buttons on your desk. The buttons carry the security point, since malware
can fake a mouse click but not a finger. You learn: displays, inputs,
two-way serial protocols, physical enclosure design. Done when a
quarantine restore cannot finish until you press the button on the robot.

Steps: define the message format between AVGuard and the robot (status
in, button presses out); an OLED face with three moods, calm (OK), alert
(threat), sleepy (AVGuard silent); an approval button, so restoring a
quarantined file or turning protection off waits for a physical press; a
panic button that disables the PC's network adapter and starts a full
scan; an RGB LED ring showing green, yellow or red; optionally a servo
that turns the head toward you on an alert; a body (project box, cardboard
or 3D print).

## Phase 6: AI supervisor and incident pipeline

An AI brain that reads AVGuard's events, judges them and explains them to
you, wired into a full incident pipeline. It comes last because it needs
every earlier phase feeding it. You learn: incident response, LLM
integration, prompt injection defence, message signing.

The pipeline, in order: detect (YARA, hashes, behaviour, Rust sensor
events); investigate (AI triage plus threat intel); human approval on the
robot button; contain (kill the process, cut the network); remediate
(disk, USB and persistence cleanup); verify (if the threat is still there,
go back to investigate); recover (roll back files from backups); learn (a
new YARA rule and an incident report). Backups and the ESP32 watchdog run
the whole time, beside the pipeline.

AI tasks: decide where the AI runs (a local model through Ollama, or a
cloud API); triage, rating each event using its context (origin,
behaviour, history); explain every detection in plain Thai or English;
correlate small events that together look like an attack; watch AVGuard's
own health (scan speed, rule file changes, missing logs); treat filenames
and file contents as untrusted data; a prompt injection test, so a file
named like an instruction cannot change the verdict; move the robot to
Wi-Fi and sign its messages (HMAC) so malware cannot fake "all OK". Done
when a simulated incident runs from detection to report, and the AI
cannot act without your button press.

## Shopping list

Phase 2 parts cost around 500 to 800 baht in total; buy Phase 5 parts only
when you get there. Prices are rough estimates. Shops: Shopee, Lazada,
ArduinoAll, Arduitronics, or Ban Mo in person.

| Item | Qty | Phase | Why |
|---|---|---|---|
| ESP32 DevKit V1 (WROOM-32, 30-pin, USB-C if possible) | 2 | 2 | One spare in case one dies |
| USB data cable (not charge-only) | 1 | 2 | Charge-only cables make the board invisible |
| Breadboard, 830 points | 2 | 2 | The ESP32 is too wide for one |
| Jumper wires, male-male and male-female | 1 pack | 2 | No soldering needed |
| LEDs, red and green | a few | 2 | Status lights |
| 220 ohm resistors | a few | 2 | Stop LEDs burning out |
| Active buzzer | 1 | 2 | The alarm sound |
| Push buttons | 3 to 5 | 2 | Acknowledge, approve |
| 0.96" OLED, SSD1306 I2C | 1 | 5 | The robot's face |
| Large arcade button | 1 | 5 | Panic button |
| WS2812 RGB LED ring, 12 or 16 LEDs | 1 | 5 | Status glow |
| SG90 micro servo | 1 | 5 | Optional head movement |
| Project box | 1 | 5 | The body |

## Portfolio checklist

Run this list at the end of every phase. A phase is not finished until all
of it is ticked.

- Code pushed to GitHub with a version tag.
- README: what it does, why it exists, how to run it.
- Demo GIF or short video showing it working.
- Architecture picture showing where it fits in the suite.
- Tests, including at least one attack you simulated.
- Limitations section: what it cannot catch, and why.
- Short post (LinkedIn or a blog) explaining one thing you learned.

## Where this repository stands, 4 October 2026

- **Phase 1** is a separate C++ project and the owner's own build; nothing
  here.
- **Phase 2** needs one small thing from AVGuard: a heartbeat line over
  serial every few seconds from the window's existing tick, and a Health
  row saying the board answered. Not built; it waits for the board.
- **Phase 3** changes a recorded decision. ROADMAP.md's "Deliberately not
  doing" list, `docs/next.md` and `docs/improvements.md` refuse process and
  network monitoring, and the seven-ideas review of 4 October refused a
  behaviour baseline on that ground. The objection was that user-mode
  Python polling observes state, not events, and misses anything shorter
  than the poll. A Rust sensor on ETW is the event-driven source the
  objection asked for, so the entry is to be rewritten, saying this, in the
  same commit that first reads the sensor's events. Until then it stands.
- **Phase 4:** the ClickFix guard is built (ROADMAP.md, "The paste guard").
  The persistence diff is next and is being built as this is written. The
  crypto clipboard swap is designed in `docs/next-6.md` with one
  measurement owed first: whether a 500 ms clipboard poll can see the
  original address at all. Beaconing and the new-destination baseline wait
  for Phase 3's sensor; threat intel lookup against a public blocklist
  reuses the hash blocklist's feed machinery once there are destinations
  to look up.
- **Phase 5** is hardware; AVGuard's side is the message format, later.
- **Phase 6:** "explain every detection" exists as the account
  (ROADMAP.md, "Explain why"); detection, event forwarding and the
  untrusted-input discipline exist. Triage, approval, containment and
  remediation do not and should not until the robot's button does.
- **The portfolio checklist, for this repository:** README yes; tests with
  simulated attacks yes; no version tag yet; no demo GIF; the architecture
  is prose ("How it is put together"), not a picture; limitations are
  stated section by section, not in one place; no post.
