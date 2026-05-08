# Building a Modular Red Team Scaffold with Built-in Control Evaluation

*Lessons from NetGuardPro's RedTeam Simulator (1 522 LoC Python, single-developer build)*

**Author** : Simon Cantin · Lévis, QC · 2026-05-08
**Status** : Public engineering report (informal). Source code in private repo, access on request.

---

## TL;DR

1. **A modular red team that targets your own defensive stack** turns a one-shot pen-test exercise into a continuous, repeatable evaluation harness — every defense agent gets a coverage score, not a binary pass/fail.
2. **SafetyGuard at the framework level** (not at the per-attack level) is the right place to enforce "no public IPs, ever" — it makes the safety property a property of the *system*, not of the *operator's discipline*.
3. **DefenseMonitor + AttackOrchestrator as siblings** is what separates a red team from a red-team-with-control-eval. The orchestrator chooses what attacks to run ; the monitor measures whether the defenses noticed. They communicate via the same WebSocket bus the rest of the suite uses, so the eval data lands in Cortex like any other event.

This note describes how those three principles play out in NetGuardPro's RedTeam component, what was easy, what was hard, and what I'd do differently next time.

---

## 1. Context : why a solo dev needs an in-process red team

NetGuardPro is a 14-program cybersecurity defense platform (firewall/IDS, antivirus, VPN, SIEM, honeypot, FIM, StrikeBack counter-measures, forensic recorder, sandbox, mobile gateway, etc.) orchestrated by **SentinelOS Cortex** on WebSocket port 8900. I'm building it solo.

The hard part of a defense-in-depth product isn't writing rules — it's *knowing whether the rules fire*. Every defensive component ships with assertions about what it should detect ; without a way to actively poke each defense and observe the response, those assertions degrade into untested folklore over a few release cycles.

Traditional answers : (a) hire a red team (no), (b) run external pentest tools like Metasploit / Caldera against the localhost (works, but those tools live outside the suite, so their findings don't end up in your event store), (c) write unit tests that mock the network (cheap, but you end up testing the mock).

**What I built instead** : a 12th program in the suite called `RedTeam`, listening on its own WebSocket port (8870), invoked by Cortex like any other agent, sharing the same event bus, the same logging, the same dashboard pattern. When it attacks, the events show up in Cortex alongside genuine threats. When defenses miss, that's a measurable gap, not a gut feeling.

---

## 2. Architecture

```
RedTeam Simulator (port 8870)
├── SafetyGuard          — restrict targets to localhost / RFC1918
│                          + rate-limit 5 attacks/min/type
├── BaseAttack           — abstract base for all simulators
├── PortScanSimulator    — TCP connect scan on 20 random ports
├── BruteForceSimulator  — rapid auth-port connections
├── SynFloodSimulator    — SYN flood (scapy when available, raw sockets otherwise)
├── DNSTunnelSimulator   — high-entropy DNS queries (DPI test)
├── HoneypotProber       — probe fake services on the localhost honeypot
├── DecoyTrigger         — trigger StrikeBack decoys
├── DPITrigger           — Snort-style signature payloads
├── FIMTamper            — create/modify test files for FIM detection
├── NetworkScanFlood     — ARP / ICMP scan burst
├── DefenseMonitor       — connect to defense agents & MEASURE detection rate
├── AttackOrchestrator   — coordinate attacks & scenarios
└── WebSocket Server     — serves live state to Cortex / dashboard
```

Three pre-defined scenarios chain attacks for realistic adversary profiles :

| Scenario | Composition | Models |
|---|---|---|
| `script_kiddie` | port_scan → brute_force | Baseline noise. Should be detected by every IDS in the suite. |
| `apt_simulation` | port_scan → dns_tunnel → dpi_trigger → fim_tamper → honeypot_prober | Stealthy lateral movement. Tests DPI + FIM + honeypot together as a chain. |
| `full_redteam` | All 9 attacks | End-to-end coverage exercise. |

Each scenario produces a structured outcome dict :
```python
{
    "scenario":     "apt_simulation",
    "started_at":   "2026-05-08T07:30:00",
    "duration_s":   12.3,
    "attacks_run":  5,
    "detections":   {
        "netguard":    3,
        "honeypot":    1,
        "fim":         1,
        "strikeback":  0,   # 0 = blind spot
    },
    "coverage":     0.80,   # 4 of 5 attacks were detected by at least one agent
    "missed":       ["dns_tunnel"],
}
```

That `coverage` field is the unit of currency for purple-teaming. It turns a 1-line bug report ("DNS tunneling went undetected") into a regression target.

---

## 3. Three design choices worth defending

### 3.1 — SafetyGuard at the framework level, not per-attack

**Wrong way :**
```python
class PortScanSimulator(BaseAttack):
    def execute(self):
        if not self._target_is_safe():  # repeated in every attack class
            return error
        ...
```

**Right way :**
```python
class AttackOrchestrator:
    def run(self, attack: BaseAttack, target_ip: str):
        ok, reason = self.safety_guard.validate(attack.name, target_ip)
        if not ok:
            return {"status": "blocked", "reason": reason}
        return attack.execute()  # attack itself never sees a non-safe target
```

The orchestrator is the only path to executing an attack. Safety becomes a property of the *system*, not of every attack author's discipline. Adding a 12th attack type can't accidentally bypass the guard.

The same pattern applies to the rate limit (5 invocations / 60s / attack type) — managed at the orchestrator level so an enthusiastic operator can't accidentally self-DoS the suite.

**Implementation detail** : `SafetyGuard.validate(attack_name, target_ip)` returns `(ok: bool, reason: str)`. The reason string ends up in the dashboard event, so a blocked attack is a *visible* event, not a silent skip. If you misconfigure a target, you find out immediately.

### 3.2 — DefenseMonitor as a separate component, not an attack

The temptation as a solo dev is to inline detection-checking inside each attack :

```python
def execute(self):
    self._send_packets()
    time.sleep(2)
    if self._netguard_logged_my_ip():
        return success
```

This couples each attack to the specific agent that should detect it, which is a brittle 1-to-N mapping (port scans should be detected by NetGuard *and* Sentinel ; DPI triggers by NetGuard *and* StrikeBack ; etc.).

`DefenseMonitor` is its own thread. It connects to all 5 defense agents (NetGuard, Honeypot, StrikeBack, FIM, Cortex) over their WebSocket ports, subscribes to their event streams, and tags every event with a timestamp. When an attack runs, the orchestrator records the attack's `started_at` ; the monitor cross-references events that arrived *after* `started_at` to determine which agents responded.

This decoupling means I can add a new defense agent (e.g., a future `mobile_gateway` IDS) and have it automatically participate in the eval just by having it emit detection events on its WebSocket bus — no edits to the attack classes.

### 3.3 — Same bus, same pattern, no special-casing

Every program in the suite (defensive or offensive) has the same shape :
- Listens on a dedicated WebSocket port
- Emits events to Cortex (correlator)
- Renders an HTML dashboard at `http://localhost:<port>`
- Speaks the same JSON event schema

The RedTeam Simulator follows this exactly. It isn't a "test mode" of the suite ; it's a full peer that happens to send adversarial traffic to other peers. The dashboards composable, the events correlated, the lifecycle managed identically.

Practical consequence : you can run the RedTeam in production-shaped traffic right next to the defensive stack. The defenses don't need a "hey, this is a drill" flag. That's exactly the point.

---

## 4. What was hard

**Distinguishing a real attack from a drill in the event store.** Once detections from RedTeam land in Cortex alongside real events, telemetry can get noisy. Solution adopted : every event from RedTeam carries a `source: "redteam_drill"` tag. Cortex policies can filter on it (e.g., StrikeBack should *not* counter-attack a drill). A simpler alternative would have been a separate test event store — I rejected it because it would mean the eval doesn't exercise the real ingest pipeline.

**Scapy availability.** The SYN flood simulator needs `scapy` for raw packet crafting, and scapy is a heavy dep that some environments can't install (corporate Windows boxes especially). The fallback path uses raw sockets and is functionally weaker but always available. A real adversary wouldn't degrade like this — but for a defensive eval it's a useful signal that the lower-bound capability is testable everywhere.

**The 5-attacks-per-minute rate limit was almost too aggressive.** The first version was 3/min and the `full_redteam` scenario kept hitting the cap. Tuned up to 5/min after instrumenting the orchestrator's wait queue. Still feels slightly arbitrary ; the right answer is probably "rate limit per scenario, not per attack type", which would let `full_redteam` fan out faster while keeping a tight cap on solo `port_scan` invocations.

**No automated CVE / 0-day discovery.** This is a known gap. The suite tests *known* attack patterns against *known* defenses. It doesn't generate novel attacks. Closing that gap would require either fuzzing-based attack synthesis or an LLM-driven attack proposer — both interesting research directions I haven't pursued yet.

---

## 5. What this would teach a fellowship project

If I were to do this work again under research supervision, the four extensions I'd prioritize :

1. **LLM-driven attack synthesis** — replace the hand-written attack classes with a prompt-driven generator (Claude as the adversary, with structured tool-use to assemble novel attack chains from primitives). Compare detection coverage of LLM-generated attacks vs hand-written ones.
2. **Coverage as a regression metric** — every release of the defensive suite re-runs `full_redteam`, posts the coverage delta to Cortex, and gates the release CI on coverage not regressing. A coverage drop = a deployment blocker, same as a unit test failure.
3. **Multi-agent purple-team for LLM-orchestrated systems** — port the same scaffold to a Claude Agent SDK / MCP server context. Adversary agent, defender agent, evaluation agent. Same bus, same orchestrator pattern. The interesting research question is whether the SafetyGuard pattern transfers cleanly to the prompt-injection / tool-use-misuse domain.
4. **Calibrating the rate limiter via on-line learning** — tune the rate cap based on observed Cortex backpressure, instead of a hard-coded 5/min. Keeps the eval from self-DoSing under load while still maximizing scenario throughput.

---

## 6. Why I'm posting this

I'm applying to the **Anthropic Fellows Program — AI Security track** for the July 2026 cohort. The job description cites *"Strengthening Red Teams: A Modular Scaffold for Control Evaluations"* as an example of fellowship output. NetGuardPro's RedTeam component is a related artifact, built solo, in production-shaped Python, with the safety + evaluation primitives baked in from the design phase.

The full source code lives in a private commercial repository — I grant temporary read-access on request to evaluators. The architecture, design rationale, and screenshots are public in this repo (`github.com/sxc3030-eng/netguard-pro`).

If you're a fellowship reviewer reading this : I'd welcome a call, written feedback, or a request for the source. Reach out via the contact links in the [README](README.md).

---

*This document is licensed under [CC BY-NC 4.0](LICENSE.md). The implementation it describes is proprietary.*
