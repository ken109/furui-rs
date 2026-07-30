# furui

[![CI](https://github.com/ken109/furui-rs/actions/workflows/ci.yaml/badge.svg)](https://github.com/ken109/furui-rs/actions/workflows/ci.yaml)

Per-process egress and ingress control for containers, enforced in the kernel
with eBPF.

Network policy is usually written in terms of addresses and ports. furui adds
the piece that is normally missing: **which process inside the container is
talking**. A policy can say "nginx may serve on 80" and mean it — if something
else in that container starts listening on 80, or if nginx starts reaching out
to somewhere it should not, the packet is dropped and the attempt is logged.

```yaml
policies:
  - container:
      name: "nginx_test"
    communications:
      - executable: "nginx"
        sockets:
          - protocol: "tcp"
            local_port: 80
```

```console
$ sudo furui example/nginx.yaml --log-level=info
 INFO furui::bpf::loader: bpf programs attached.
 INFO furui::bpf::events::traffic: event="ingress" action="pass" container_id="ce6799b9bd52"
      comm="nginx" family="IP" protocol="TCP" source_addr="172.17.0.1" source_port=53040
      destination_addr="172.17.0.2" destination_port=80
 INFO furui::bpf::events::traffic: event="egress" action="drop" container_id="ce6799b9bd52"
      comm="wget" family="IP" protocol="TCP" source_addr="172.17.0.2" source_port=57292
      destination_addr="1.1.1.1" destination_port=80
```

> [!WARNING]
> furui is **default-deny for every running container** the moment it starts.
> A container with no matching policy has all of its traffic dropped. Try it
> somewhere you do not mind breaking first.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Install](#install)
- [Usage](#usage)
- [Policy reference](#policy-reference)
- [Development](#development)
- [Project layout](#project-layout)

## How it works

Two halves cooperate through eBPF maps.

**In the kernel**, tc classifiers attached to every `veth*` interface see each
packet entering or leaving a container. To decide, a classifier needs to know
which process a packet belongs to — so kprobes on `inet_bind`, `inet6_bind`,
`tcp_connect`, `udp_send_skb` and `udp_v6_send_skb`, plus a
`sched:sched_process_exit` tracepoint, keep a map of *which executable holds
which port* in each container, updated as sockets come and go.

**In userspace**, furui watches the container runtime, resolves policies into
map entries, and drains the classifiers' verdicts into structured logs.

```
                policy.yaml ──┐
                              ▼
  docker / CRI ──────► furui (userspace)
   container events         │  fills
                            ▼
                     ┌──────────────┐
                     │  eBPF maps   │  policies, container IPs, port→process
                     └──────┬───────┘
                            │ read by
        ┌───────────────────┴───────────────────┐
        ▼                                       ▼
  tc classifiers                         kprobes / tracepoint
  (veth ingress+egress)                  (bind, connect, exit)
   pass / drop                            track port ownership
        │
        └────── perf events ──────► logs
```

A packet passes if any rule for its container matches. Rules are checked from
the narrowest specification outwards — see
[`furui-ebpf/src/README.md`](furui-ebpf/src/README.md) for the exact order,
which is generated from the event definitions rather than written by hand.

Both the policy file and the set of running containers are watched live:
editing a policy takes effect within a second, and containers starting or
stopping re-resolve their names to ids without a restart.

## Requirements

- **Linux.** furui loads eBPF programs and reads `/proc`; it cannot run on
  macOS or Windows. Use a VM.
- A kernel with **BTF** enabled — that is, `/sys/kernel/btf/vmlinux` exists
  (`CONFIG_DEBUG_INFO_BTF=y`). Distribution kernels generally have it.
- **root**, to attach kprobes and tc classifiers.
- **docker**, or a **CRI** runtime listening on
  `/run/containerd/containerd.sock`.

Verified on Linux 6.8, on both `x86_64` and `aarch64`.

## Install

Prebuilt `x86_64` and `aarch64` binaries are attached to every CI run as
artifacts. They are statically linked against musl, so they need nothing on the
target host.

To build from source, see [Development](#development) — the eBPF half needs a
nightly toolchain, LLVM and a few code generators.

## Usage

```console
$ furui --help
Usage: furui [OPTIONS] <POLICY_PATH>

Arguments:
  <POLICY_PATH>  Path to the policy file to enforce

Options:
  -e, --container-engine <CONTAINER_ENGINE>
          [default: docker] [possible values: docker, kubernetes-cri]
      --log-level <LOG_LEVEL>
          [default: info] [possible values: error, warn, info, debug, trace]
      --log-fmt <LOG_FMT>
          [default: text] [possible values: json, text]
  -h, --help
          Print help
```

```bash
# docker (the default)
sudo furui policy.yaml --log-level=info

# Kubernetes CRI
sudo furui -e kubernetes-cri policy.yaml

# structured output, for shipping somewhere
sudo furui policy.yaml --log-fmt=json
```

Every verdict is one log record. In JSON:

```json
{
  "timestamp": "2026-07-30T09:40:33.469852Z",
  "level": "INFO",
  "fields": {
    "event": "egress",
    "action": "drop",
    "container_id": "ce6799b9bd52",
    "comm": "wget",
    "family": "IP",
    "protocol": "TCP",
    "source_addr": "172.17.0.2",
    "source_port": 57292,
    "destination_addr": "1.1.1.1",
    "destination_port": 80
  },
  "target": "furui::bpf::events::traffic"
}
```

furui detaches its tc qdiscs on exit. The kprobes and tracepoints go away with
the process.

## Policy reference

A policy file is a list of policies, each naming one container and the
communications allowed from it.

```yaml
policies:
  - container:
      name: "furui_wordpress"      # docker/CRI container name, no leading "/"
    communications:
      - executable: "apache2"      # process name, as in /proc/<pid>/comm
        sockets:
          - protocol: "tcp"
            local_port: 80         # accept connections to our port 80
          - protocol: "tcp"
            remote_host: "furui_db"   # another container, by name
            remote_port: 3306
          - protocol: "tcp"
            remote_host: "api.wordpress.org"   # or a DNS name
            remote_port: 443
      - executable: "php"
        icmp:
          - version: "v4"
            type: 8                # echo request
```

### `container`

| Field  | Type   | Notes |
| ------ | ------ | ----- |
| `name` | string | Container name as the runtime reports it, without docker's leading `/`. Re-resolved to an id whenever containers change; a policy for a container that is not running simply matches nothing. |

### `communications[]`

| Field        | Type   | Notes |
| ------------ | ------ | ----- |
| `executable` | string | Process name, matched against `/proc/<pid>/comm`, which the kernel limits to 15 characters. With no `sockets` and no `icmp`, this allows **everything that process does**. |
| `sockets`    | list   | Allowed TCP/UDP communications. Optional. |
| `icmp`       | list   | Allowed ICMP communications. Optional. |

### `sockets[]`

| Field         | Type            | Default  | Notes |
| ------------- | --------------- | -------- | ----- |
| `protocol`    | `tcp` \| `udp`  | any      | Omit to match either. |
| `local_port`  | 1–65535         | any      | The container's own port. |
| `remote_port` | 1–65535         | any      | The other end's port. |
| `remote_host` | string          | any      | A DNS name, a literal address, or **another container's name**. Resolved at load time and expanded into one rule per address. |

### `icmp[]`

| Field         | Type          | Default | Notes |
| ------------- | ------------- | ------- | ----- |
| `version`     | `v4` \| `v6`  | —       | **Required.** furui refuses to apply a policy that omits it. |
| `type`        | 0–255         | —       | **Required.** ICMP type, e.g. `8` for echo request, `0` for echo reply. |
| `code`        | 0–255         | any     | |
| `remote_host` | string        | any     | As for sockets. |

IPv6 neighbour discovery (types 135 and 136) is always allowed — policing it
would break the container's networking before any policy could apply.

### Notes on matching

- An omitted field is a wildcard. Anything not permitted by some rule is
  dropped.
- `remote_host` that resolves to nothing produces **no** rules, rather than a
  wildcard — an unreachable name fails closed.
- Names are resolved when the policy is loaded, not per packet. If a DNS record
  or a container's address changes, touch the policy file to reload.

More examples live in [`example/`](example/), including a
[WordPress + MySQL setup](example/wordpress/) with two containers talking to
each other.

## Development

Everything below assumes Linux with BTF, as above.

### Toolchain

```bash
# furui-ebpf pins nightly via rust-toolchain.toml and needs rust-src for
# -Z build-std; rustfmt.toml uses unstable options, so fmt needs nightly too.
rustup toolchain install stable
rustup toolchain install nightly --component rust-src

# bpf-linker links against the system LLVM; protobuf-src builds protoc
sudo apt install llvm-19-dev libpolly-19-dev clang-19 cmake build-essential
export PATH=/usr/lib/llvm-19/bin:$PATH

# bpftool must be one that exists for your kernel; aya-tool shells out to it
sudo apt install linux-tools-generic

cargo install bpf-linker bindgen-cli
cargo install aya-tool --git https://github.com/aya-rs/aya.git
```

### Kernel bindings

```bash
cargo xtask codegen
```

Generates `furui-ebpf/src/vmlinux.rs` from the running kernel's BTF. It is not
committed. The list of types lives in [`xtask/src/main.rs`](xtask/src/main.rs);
`codegen` fails loudly if any of them is missing rather than letting it surface
as a confusing compile error.

### Build and run

```bash
cargo build                                        # builds both halves
cargo xtask run -- example/nginx.yaml --log-level=info   # builds, then sudo
```

`furui`'s build script compiles `furui-ebpf` for `bpf{el,eb}-unknown-none` and
embeds the object, so there is no separate eBPF build step.

### Tests

```bash
cargo test                     # unit tests, no privileges needed
sudo -E cargo test -- --ignored   # end-to-end, needs root and docker
```

The end-to-end test starts a container, loads `example/nginx.yaml`, and asserts
that the policy passes traffic to port 80 while dropping the container's
outbound connections — checking the baseline first, so a broken fixture cannot
pass for successful enforcement.

To check that a change to the eBPF side did not make the programs more
expensive, compare instruction counts before and after:

```bash
sudo bpftool prog dump xlated name ingress | wc -l
```

## Project layout

| Crate          | What it is |
| -------------- | ---------- |
| `furui`        | The userspace daemon: runtime integration, policy loading, map management, event logging. |
| `furui-ebpf`   | The kernel side: tc classifiers under `tc/`, kprobes and tracepoints under `probes/`. Builds only for `bpf*-unknown-none`. |
| `furui-common` | Types shared across that boundary — map keys and values, and the event structs written to perf buffers. |
| `furui-macros` | Derives that generate the policy lookups from the event definitions. |
| `xtask`        | Repository automation (`cargo xtask codegen`, `cargo xtask run`). |
