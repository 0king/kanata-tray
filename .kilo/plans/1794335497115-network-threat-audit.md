# Plan: Network-threat audit of kanata-tray (app + dependencies)

## Goal
Produce a defensible inventory of every network request the kanata-tray binary can make (any protocol), across the application source and all Go/CGo dependencies, plus an honest statement of what cannot be ruled out.

## Bottom-line answer (for the user)
**No — you cannot guarantee completeness.** Network behavior can be hidden behind encryption, runtime-computed destinations, CGO/native code, compiler/toolchain injection, or a future compromised dependency release. You *can* achieve high-coverage static inventory plus empirical confirmation via dynamic analysis, but not a proof of absence.

## Scope decisions (resolved)
- Target OS: Linux only (this checkout). systray/native surface differs on Windows/macOS; document that as out of scope.
- Localhost-only constraint: the app must not send or receive any traffic to/from non-localhost addresses (127.0.0.0/8, ::1, and Unix domain sockets only). Any observed non-localhost socket, packet, or connection is a finding.
- Static analysis of the vendored dependency tree is the primary method; dynamic analysis (sandbox + network interception via tcpdump) is required to catch runtime-computed/encrypted destinations.
- Acceptance criterion = a documented network inventory + residual-risk list, not a guarantee.
- `getlantern/systray` replacement is out of scope for this audit (noted as a risk-reduction recommendation only).

## Known network surface in this repo (from source read)
- `runner/tcp_client/tcp_client.go` — TCP to `localhost:<port>` (kanata IPC, client side).
- `app/controlserver/tcp_control_server.go` — HTTP server on `127.0.0.1:<port>` (inbound; `go-chi/chi`, `net/http`).
- `github.com/getlantern/systray` — CGO-dependent, unmaintained (3+ yrs, 97 open issues, 17 open PRs); native GUI toolkit may issue platform-specific calls; network surface opaque to Go source scan.
- `github.com/skratchdot/open-golang` — spawns external `open`/browser commands (induces network indirectly).
- `go.opentelemetry.io/otel` — traces/metrics; network only if an exporter is configured.
- `golang.org/x/sys` — low-level syscalls; potential raw-socket use.

## Tasks

1. Enumerate the full module graph
   - Run `go list -m all` to capture every direct + transitive module and version.
   - Commit `go.sum` and pin versions; disallow `go get -u` in prod builds.

2. Vendor dependencies
   - `go mod vendor` and commit the vendor tree so builds are reproducible and independent of the public module proxy.
   - All subsequent static scans run against `vendor/` (what actually gets compiled).

3. Static source scan for network APIs (all protocols/layers)
   - Parse/Grep app + `vendor/` for: `net`, `net/http`, `net/url`, `crypto/tls`, `net/rpc`, `syscall`, `golang.org/x/sys`, `os/exec`, and transport-specific pkgs (websocket, grpc, mqtt, etc.).
   - Also scan for raw-socket and low-level syscall usage: `syscall.Socket`, `syscall.Bind`, `syscall.Connect`, `syscall.Sendto`, `syscall.Recvfrom`, `AF_PACKET`, `AF_INET`, `AF_INET6`, `AF_UNIX`, `SOCK_RAW`, `SOCK_DGRAM`, `SOCK_STREAM`, `IPPROTO_*`, `inet_ntoa`, `gethostbyname`, `getaddrinfo`.
   - Record each call site, file:line, protocol family (AF_INET/AF_INET6/AF_UNIX/AF_PACKET), socket type, and any string-literal destination (host/IP/port/URL).
   - Flag any string-literal or computed destination that is not localhost (127.0.0.0/8, ::1, Unix domain socket) as a finding.
   - Flag runtime-computed destinations (env vars, config fields, DNS lookups) as "unresolvable statically."

4. CGO / native dependency audit
   - Identify all C/C++/assembly/syso files pulled into the build (primarily via `getlantern/systray` and its GUI toolkit deps).
   - Scan native sources for socket/syscall/network APIs at all layers: `socket`, `connect`, `bind`, `sendto`, `recvfrom`, `setsockopt`, `ioctl`, `SOCK_RAW`, `AF_PACKET`, `AF_INET`, `AF_INET6`, `AF_UNIX`, `IPPROTO_*`, `WinInet`, `WinHTTP`, `libcurl`, `libnotify`, `pcap`, `libpcap`, `BPF`, `ioctl(SIOCGIF*)`, `ioctl(SIOCSIFFLAGS)`.
   - Document that native binaries cannot be fully verified by Go source scan.

5. Binary-level network artifact scan
   - Build the binary (`CGO_ENABLED=1` as the project requires).
   - Run `strings`/`nm`/`objdump` or a binary scanner (trivy/syft/grype) on the artifact to find embedded IPs, domains, URLs, and network-related imports/symbols (including raw-socket symbols: `socket`, `connect`, `sendto`, `recvfrom`, `setsockopt`, `ioctl`, `pcap_open`, `libnet`, `libpcap`).
   - Compare against static source findings; delta = native-only or linker-introduced network surface.

6. Dynamic / runtime network analysis (required — all protocols, all sockets, lowest layer)
   - Prerequisites: `go`, `gcc`, `tcpdump`, `ss`, `xvfb` (install if missing; confirmed present: go, tcpdump, ss at /usr/bin, gcc at /usr/bin/gcc).
   - Build the binary: `CGO_ENABLED=1 go build -o kanata-tray .` (project requires CGO for systray).
   - Run the binary in an isolated environment (container or VM) with no access to internal secrets/credentials.
   - Start Xvfb: `Xvfb :99 -screen 0 1024x768x16 &` then `export DISPLAY=:99` to give systray a display session.
   - Packet capture (lowest network layer, link layer upward): start `tcpdump -i any -s 0 -w capture.pcap` before launching; this captures Ethernet/IP/ARP and all transport protocols (TCP, UDP, ICMP, IGMP, raw IP, multicast) regardless of application protocol.
   - Socket enumeration during runtime: poll `ss -tulpn`, `ss -tulnp`, `ss -x`, `ss -s` and `/proc/net/{tcp,tcp6,udp,udp6,raw,raw6,netlink,unix}` before launch, during UI exercise, and at shutdown to enumerate every listening/connected/raw/unix socket (pid, inode, state, local/remote address:port).
   - Launch the app and exercise UI paths: open tray menu, click items, hit control-server HTTP endpoints (`/start_all_default`, `/stop_all`, etc.) to cover more code paths.
   - Leave running long enough to catch delayed/periodic beacons (recommend ≥5 min).
   - Stop tcpdump, parse pcap (`tcpdump -r capture.pcap -nn` or tshark) to list every packet: timestamp, src/dst MAC, src/dst IP:port, IP protocol number, Ethernet type, DNS queries/responses.
   - Cross-correlate pcap packets with socket table entries by local address:port and pid.
   - Record every observed connection/socket/packet: timestamp, src/dst IP:port, protocol (IP protocol number + transport), socket type, state, pid, DNS name resolved.
   - Enforce localhost-only: any socket, packet, or connection with a remote address outside 127.0.0.0/8, ::1, or a Unix domain socket is recorded as a finding and investigated.
   - Merge observed destinations/sockets into the inventory. Any socket or packet not in the static inventory is a finding to investigate.

7. Document findings
   - Network inventory table: component, file:line, protocol, destination (literal vs computed), confidence.
   - Residual-risk list: what could not be ruled out (encrypted blobs, CGO native code, future dependency compromise, dependency confusion).
   - Mitigation recommendations: pin go.sum, vendor, replace unmaintained systray, build offline, SBOM per release, periodic re-audit.

## Validation
- Every static network call site (all protocol families, socket types, raw-socket syscalls) has a corresponding inventory row.
- `go.sum` matches vendored modules (`go mod verify`).
- Binary artifact contains no unexpected embedded IP/domain strings or raw-socket symbols beyond the inventory.
- Dynamic run captures: (a) every packet at link layer upward via tcpdump pcap (any IP protocol number, Ethernet type), (b) every socket via `ss` and `/proc/net/*` (tcp/tcp6/udp/udp6/raw/raw6/netlink/unix), cross-correlated by address:port and pid.
- All observed sockets/packets/connections must be localhost-only (127.0.0.0/8, ::1, or Unix domain socket). Any non-localhost traffic is a failing finding.
- Any socket, packet, or connection not in the static inventory is recorded as a finding and investigated.
- tcpdump/ss tooling confirmed present in this environment (go, tcpdump, ss at /usr/bin).

## Resolved decisions
- Dynamic runtime analysis: in scope, using tcpdump (confirmed at /usr/bin/tcpdump).
- Xvfb: in scope, used to provide a display session for systray (install `xvfb` if missing).
- OS target: Linux only.
- Build toolchain: Go confirmed at /usr/bin/go; gcc confirmed at /usr/bin/gcc; CGO_ENABLED=1 required for systray.
- Socket inspection: ss confirmed at /usr/bin/ss.
- localhost-only constraint: any socket/packet/connection outside 127.0.0.0/8, ::1, or Unix domain socket is a failing finding.
- systray replacement: out of scope (risk-reduction recommendation only).
