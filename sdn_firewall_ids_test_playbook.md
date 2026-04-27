# SDN Firewall/IDS Test Playbook

## 1. Purpose

This playbook documents the attack-generation commands used to validate the SDN firewall and intrusion detection system. Its purpose is to show:

- the traffic pattern each command generates
- the meaning of the important command flags
- the expected detection behavior
- how the controller-driven firewall/IDS responds
- how host blocking or quarantine is applied in the SDN environment

The playbook is aligned with a controller-driven SDN security workflow in which:
- traffic is first observed by the controller through OpenFlow packet-in and flow behavior
- threshold-based IDS logic evaluates suspicious behavior
- optional ML support may enrich or strengthen the decision path
- the firewall/mitigation logic applies a block or quarantine rule to the attacking source host
- the dashboard and capture pipeline record the event for monitoring and later inspection

---

## 2. Assumed Lab Context

Example Mininet addressing typically looks like this:

- `h1 = 10.0.0.1`
- `h2 = 10.0.0.2`
- `h3 = 10.0.0.3`
- `h4 = 10.0.0.4`
- `h5 = 10.0.0.5`

In your workflow, the attacking host is usually the host that launches the scan or flood, while the victim is one or more target hosts.

---

## 3. Detection and Blocking Model

Your system is best described as a **threshold-first SDN firewall/IDS with optional ML enhancement**.

### 3.1 What the system watches for
The controller and IDS logic typically observe patterns such as:

- unusually high packet rates
- SYN-heavy traffic
- large numbers of destination ports probed
- large numbers of hosts contacted in a short interval
- repeated failed or incomplete connection attempts
- ICMP or UDP flood-like behavior
- repeated suspicious windows over time

### 3.2 How the system blocks
When a source host is classified as malicious or sufficiently suspicious:

1. the IDS raises an alert
2. the source IP or host is marked as malicious or quarantined
3. the controller installs OpenFlow drop rules or firewall block rules
4. future traffic from that source is denied
5. the blocked host appears in monitoring state and may require manual unblock

So, in practice, your controller is not “shutting down the host”; it is **installing flow rules that prevent the switch from forwarding that host’s traffic**.

---

# 4. Command Playbook

## 4.1 TCP SYN scan of selected ports

```bash
h1 nmap -sS -p 22,80,443 10.0.0.2
```

### What it does
This command performs a **TCP SYN scan** against host `10.0.0.2`, but only on ports `22`, `80`, and `443`.

### Important flags
- `nmap` — network scanning tool
- `-sS` — SYN scan, often called a half-open scan
- `-p 22,80,443` — restricts scanning to those ports only

### How it works
Nmap sends SYN packets to the target ports:
- if the target replies with **SYN-ACK**, the port is likely open
- if the target replies with **RST**, the port is likely closed
- the scanner usually avoids completing the full TCP handshake

### What your system should detect
This may trigger:
- **port-scan detection**, if multiple ports are probed in a short window
- possibly **failed-connection or suspicious SYN behavior**, depending on your thresholds

### How your system blocks it
If the threshold for suspicious multi-port probing is crossed:
- the controller identifies `h1` as the source
- the IDS raises a scan alert
- the firewall/mitigation service installs a drop rule for traffic from `10.0.0.1`
- further probing from `h1` is blocked

---

## 4.2 Broad TCP SYN scan of the target

```bash
h1 nmap -sS 10.0.0.2
```

### What it does
This performs a broader SYN scan of the default port set on the target host.

### Important flags
- `-sS` — SYN scan

### How it works
Instead of scanning only a few ports, Nmap probes its default important port list. This usually creates a more visible scan pattern than the previous command.

### What your system should detect
This should more strongly support:
- **port-scan detection**
- **suspicious connection-rate detection**

### How your system blocks it
Because more ports are touched within the detection window, this should cross the scan threshold faster than a small three-port check. The source host is then quarantined or blocked through an OpenFlow rule.

---

## 4.3 Large TCP port sweep

```bash
h1 nmap -sS -p 1-1000 10.0.0.2
```

### What it does
This scans ports `1` through `1000` on the target using SYN probes.

### Important flags
- `-sS` — SYN scan
- `-p 1-1000` — explicitly scan ports 1 to 1000

### How it works
This produces a much denser and more obvious scan signature, because the source rapidly attempts connections to many ports on the same target.

### What your system should detect
This is a strong candidate for:
- **port-scan detection**
- **high suspicious connection count**
- possibly **SYN flood-like behavior**, depending on implementation

### How your system blocks it
The source host is typically blocked quickly because:
- unique destination port count rises sharply
- repeated failed or incomplete connections accumulate
- suspicious window counters grow rapidly

---

## 4.4 Multi-host SYN scan

```bash
h1 nmap -sS 10.0.0.2 10.0.0.3 10.0.0.4 10.0.0.5
```

### What it does
This runs a SYN scan against multiple target hosts.

### Important flags
- `-sS` — SYN scan
- multiple IPs — multiple hosts are scanned in one command

### How it works
Instead of scanning many ports on one machine only, the attacker fans out across several hosts.

### What your system should detect
This is likely to trigger:
- **host-scan detection**
- and possibly **combined host-and-port scanning behavior**

### How your system blocks it
The IDS should identify that one source is contacting many destinations in a short time window. Once the host-scan threshold is met, the source host is quarantined and future traffic is denied.

---

## 4.5 SYN scan with service detection

```bash
h1 nmap -sS -sV 10.0.0.2
```

### What it does
This performs a SYN scan and then attempts **service version detection** on identified open services.

### Important flags
- `-sS` — SYN scan
- `-sV` — service/version detection

### How it works
After identifying ports that look open, Nmap sends additional probes to learn what service is running.

### What your system should detect
This may create:
- scan behavior across ports
- extra probing after open-port discovery
- increased suspicious connection activity

### How your system blocks it
Your IDS may either:
- block during the initial scan phase, or
- allow initial scan evidence to accumulate and then block once the extra version-probing traffic confirms malicious intent

---

## 4.6 UDP scan of selected ports

```bash
h1 nmap -sU -p 53,67,123 10.0.0.2
```

### What it does
This sends UDP probes to common UDP service ports:
- `53` — DNS
- `67` — DHCP
- `123` — NTP

### Important flags
- `-sU` — UDP scan
- `-p 53,67,123` — selected UDP ports

### How it works
UDP scanning is different from TCP scanning because there is no handshake. The scanner infers state from:
- ICMP unreachable responses
- application replies
- silence or timeout

### What your system should detect
Your IDS may detect:
- **UDP scan behavior**
- suspicious destination-port diversity
- repeated failed or unanswered probes

### How your system blocks it
If UDP scan thresholds are implemented, the source host is marked suspicious and then blocked with a flow rule or source-based firewall block.

---

## 4.7 ICMP flood from h3 to h5

```bash
h3 hping3 --icmp --flood 10.0.0.5
```

### What it does
This generates a very high-rate **ICMP flood** from `h3` to `10.0.0.5`.

### Important flags
- `hping3` — packet crafting and traffic generation tool
- `--icmp` — use ICMP packets
- `--flood` — send packets as fast as possible

### How it works
The command aggressively transmits ICMP traffic with minimal pacing, creating a flood condition.

### What your system should detect
This should strongly trigger:
- **packet-flood detection**
- high packet rate anomaly
- possibly target-directed DoS behavior

### How your system blocks it
Because the packet rate is extreme, this should be one of the easiest attacks for a threshold-based IDS to detect. The controller then installs a drop rule for `h3`, preventing additional ICMP flood traffic from being forwarded.

---

## 4.8 TCP SYN flood to port 443

```bash
h1 hping3 -S -p 443 --flood 10.0.0.2
```

### What it does
This generates a **TCP SYN flood** targeting port `443` on `10.0.0.2`.

### Important flags
- `-S` — set the SYN flag
- `-p 443` — target destination port 443
- `--flood` — send at maximum rate

### How it works
A very large number of SYN packets are sent rapidly, attempting to overwhelm the target or create excessive half-open connection state.

### What your system should detect
This is a classic case for:
- **SYN flood detection**
- high packet-rate detection
- failed or incomplete connection surge

### How your system blocks it
Once SYN-related thresholds are exceeded:
- the IDS classifies the source as severe or malicious
- the controller installs a block rule for the source IP
- traffic from `h1` is denied before it can continue flooding

---

## 4.9 UDP flood to port 53

```bash
h1 hping3 --udp -p 53 --flood 10.0.0.2
```

### What it does
This generates a high-rate UDP flood toward port `53` on `10.0.0.2`.

### Important flags
- `--udp` — send UDP packets
- `-p 53` — target UDP port 53
- `--flood` — transmit as fast as possible

### How it works
The attacker floods a service port with high-rate UDP packets, producing DoS-like traffic volume.

### What your system should detect
Likely triggers:
- **packet-flood detection**
- possibly **service-targeted UDP abuse**
- suspicious packet-rate spike

### How your system blocks it
The source host is blocked when the packet-rate threshold or UDP flood threshold is crossed.

---

## 4.10 ICMP flood to one host

```bash
h1 hping3 --icmp --flood 10.0.0.2
```

### What it does
This sends a high-rate ICMP flood from `h1` to `10.0.0.2`.

### Important flags
- `--icmp` — use ICMP
- `--flood` — maximum send rate

### How it works
This is a simpler flood than the TCP SYN flood because it does not rely on TCP state; it just overwhelms the destination with rapid ICMP packets.

### What your system should detect
This should trigger:
- **ICMP flood / packet flood detection**
- abnormal packet-rate escalation

### How your system blocks it
The controller installs a source block or quarantine rule once the threshold is crossed.

---

## 4.11 Slow / stealthier SYN scan

```bash
h1 nmap -sS -T2 -f --randomize-hosts 10.0.0.2
```

### What it does
This attempts a more cautious SYN scan with slower timing and packet fragmentation behavior.

### Important flags
- `-sS` — SYN scan
- `-T2` — slower timing template
- `-f` — packet fragmentation
- `--randomize-hosts` — randomize target order when multiple hosts are used

### How it works
This is designed to reduce obvious burst patterns and make scanning appear less aggressive.

### What your system should detect
This is important because it tests whether your system can detect:
- **lower-rate suspicious behavior**
- repeated suspicious windows
- near-threshold scan behavior accumulating over time

### How your system blocks it
A well-tuned hybrid or threshold-first IDS may not block immediately on one weak window. Instead, it should:
- record repeated suspicious observations
- accumulate source history
- escalate once repeated suspicious windows or agreement with ML support becomes strong enough

This is one of the best commands for demonstrating why **hybrid mode** matters.

---

# 5. Tag / Flag Quick Reference

## Nmap flags
- `-sS` — TCP SYN scan
- `-sU` — UDP scan
- `-sV` — service/version detection
- `-p` — select ports
- `-T2` — slower timing profile
- `-f` — fragment packets
- `--randomize-hosts` — randomize scanning order of targets

## hping3 flags
- `-S` — set TCP SYN flag
- `--icmp` — use ICMP packet type
- `--udp` — use UDP packets
- `-p` — target port
- `--flood` — transmit at maximum possible rate

---

# 6. Expected Mapping Between Attack Type and IDS Behavior

| Attack pattern | Expected IDS tag / category | Likely response |
|---|---|---|
| Small SYN port probe | Suspicious port scan | Alert, then block if threshold crossed |
| Large multi-port SYN scan | Port scan / severe suspicious behavior | Fast block |
| Multi-host SYN scan | Host scan | Block |
| UDP service probing | UDP scan | Alert or block depending on thresholds |
| ICMP flood | Flood / DoS | Immediate block |
| SYN flood | SYN flood / severe DoS | Immediate block |
| UDP flood | Flood / DoS | Immediate block |
| Slow stealth scan | Repeated suspicious windows / hybrid-elevated scan | Delayed but meaningful escalation |

---

# 7. How to Describe the Blocking Mechanism in Your Report

A good academic description is:

> When malicious or sufficiently suspicious traffic is detected, the SDN controller translates the IDS decision into programmable enforcement by installing OpenFlow drop rules or source-based quarantine rules on the switch. This prevents subsequent packets from the offending host from being forwarded through the network. In this way, the system links monitoring, detection, and mitigation in a single controller-driven workflow.

A more project-specific version is:

> The system adopts a threshold-first intrusion detection strategy in which severe flooding or scanning behavior is treated as authoritative evidence for mitigation. Once the source host exceeds the configured detection thresholds, the controller updates firewall state and installs blocking rules against the host, thereby isolating it from the protected SDN environment. In hybrid mode, repeated suspicious behavior or strong machine-learning evidence can further support escalation where a single threshold window may not be sufficient on its own.

---

# 8. Suggested Operational Playbook Format for Demo Use

For each demo scenario, present:

1. **Attack command**
2. **Traffic type**
3. **What the command is intended to test**
4. **Expected IDS label**
5. **Expected controller action**
6. **Expected dashboard/capture evidence**
7. **Manual unblock procedure**, if applicable

Example:

### Scenario: SYN flood against web service
Command:
```bash
h1 hping3 -S -p 443 --flood 10.0.0.2
```

Expected behavior:
- IDS detects SYN-dominant flood traffic
- Controller marks `h1` malicious
- Firewall installs block rule for source host
- Dashboard shows blocked host and alert reason
- Capture snapshot is preserved for analysis

---

# 9. Important Note for Accuracy

One small correction in your list:

```bash
h1 hping3 --udp -p 53 --flood 10.0.0.2, h1 hping3 --icmp --flood 10.0.0.2
```

That line contains **two commands joined by a comma**, so they should be treated separately:

```bash
h1 hping3 --udp -p 53 --flood 10.0.0.2
```

```bash
h1 hping3 --icmp --flood 10.0.0.2
```

Also, the correct Nmap flag is usually:

```bash
--randomize-hosts
```

not `--randomize-host`.

---
