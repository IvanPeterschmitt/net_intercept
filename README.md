# Net Intercept

## Linux IPv4 Monitoring and Filtering Module

**Net Intercept** is a Linux kernel module written in C that intercepts incoming IPv4 packets, extracts their essential information, and applies a configurable filtering rule. The project relies directly on **Netfilter** and **Kbuild**, with no external application dependency in the processing path.

The project has two goals: provide a minimal and readable filtering component while demonstrating a rigorous systems development approach through separation of responsibilities, input validation, error handling, and executable integration tests.

> Educational and technical project. This module is not a replacement for a production firewall and should be tested in a virtual machine or laboratory environment.

## Highlights

- Direct integration into the Linux networking path through the `NF_INET_PRE_ROUTING` hook.
- Defensive parsing of IPv4, TCP, and UDP headers from `struct sk_buff`.
- Combinable filtering by source address, destination address, protocol, and ports.
- Support for individual IPv4 addresses and CIDR notation, such as `192.168.1.0/24`.
- Two operating modes: logging (`log`) or dropping (`drop`).
- Module parameters inspectable with `modinfo` and configurable when loading with `insmod`.
- Shell tests covering compilation, loading, unloading, and ICMP, TCP, and UDP traffic observation.

## Architecture

```text
                Incoming IPv4 packet
                         |
                         v
              NF_INET_PRE_ROUTING
                         |
                         v
             net_interception.c
    Netfilter hook orchestration
                         |
          +--------------+--------------+
          |                             |
          v                             v
   packet_parser.c               packet_filter.c
 IP/TCP/UDP extraction       criteria comparison
          |                             |
          +--------------+--------------+
                         |
                         v
              NF_ACCEPT ou NF_DROP
                         |
                         v
              Kernel log via dmesg
```

### Component Responsibilities

| File | Responsibility |
| --- | --- |
| `net_interception.c` | Parameter declarations, hook registration, and final decision. |
| `packet_parser.c` | Data availability checks and extraction of IP, TCP, and UDP headers. |
| `param_parser.c` | Validation and conversion of text parameters: mode, CIDR, protocol, and ports. |
| `packet_filter.c` | Applies filtering criteria to an already parsed packet structure. |
| `tests/` | Shell integration scenarios requiring network and kernel privileges. |
| `Makefile` | Kbuild wrapper for building and cleaning the out-of-tree module. |

## How It Works

When loaded, the module:

1. Parses and validates the parameters provided by the user.
2. Builds the IPv4 masks required for CIDR comparisons.
3. Registers an IPv4 Netfilter hook at priority `NF_IP_PRI_FIRST`.
4. Parses each IPv4 packet that contains enough data to be processed.
5. Applies all active criteria.
6. Returns `NF_ACCEPT` or `NF_DROP` and logs processed packets.

Malformed or insufficiently linearized packets are skipped with a debug trace and accepted. This prevents a parsing error from unintentionally turning the module into a traffic choke point.

## Available Parameters

Parameters are evaluated when the module is loaded. By default, all traffic is targeted and matching packets are logged.

| Parameter | Values | Example | Description |
| --- | --- | --- | --- |
| `mode` | `log`, `drop` | `mode=drop` | Action applied to packets matching all criteria. |
| `ip_src` | IPv4 or CIDR | `ip_src=10.0.0.0/8` | Target source address or network. |
| `ip_dest` | IPv4 or CIDR | `ip_dest=192.168.1.10` | Target destination address or network. |
| `proto` | empty, `icmp`, `tcp`, `udp` | `proto=tcp` | Target Layer 4 protocol. An empty value means all protocols. |
| `port_src` | `1` to `65535` | `port_src=443` | Target source port for TCP or UDP. |
| `port_dest` | `1` to `65535` | `port_dest=22` | Target destination port for TCP or UDP. |

Active criteria are cumulative: a packet must match the specified addresses, protocol, and ports to trigger the selected mode. With `mode=drop`, the module rejects a configuration with no explicit criteria to prevent accidentally dropping all incoming IPv4 traffic.

## Prerequisites

- Linux with headers for the running kernel.
- `build-essential` or an equivalent compilation environment.
- `make`, `gcc`, and Kbuild tools.
- `iproute2` to detect the interface in the tests.
- `root` privileges or equivalent capabilities to load a module and read kernel logs.
- For traffic tests: `ping`, `curl`, and `dig` (`dnsutils`).

Debian/Ubuntu installation:

```bash
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r) iproute2 iputils-ping curl dnsutils
```

## Build

From the project directory:

```bash
make
```

The build produces `net_intercept.ko` through the current kernel's Kbuild system. To remove build artifacts:

```bash
make clean
```

To inspect the module metadata and exposed parameters:

```bash
modinfo ./net_intercept.ko
```

## Usage

### Log TCP Traffic to a Server

```bash
sudo insmod ./net_intercept.ko \
    mode=log \
    proto=tcp \
    ip_dest=192.168.1.10 \
    port_dest=443
```

### Block UDP Traffic to a Network

```bash
sudo insmod ./net_intercept.ko \
    mode=drop \
    proto=udp \
    ip_dest=10.0.0.0/8
```

### Watch the Logs

```bash
sudo dmesg -w | grep NET_INTERCEPT
```

Events are written to the kernel log with the `[NET_INTERCEPT]` prefix. The format includes the numeric protocol, IPv4 addresses, and, for TCP/UDP, the ports.

### Unload the Module

```bash
sudo rmmod net_intercept
```

Unloading disables the Netfilter hook registered by the module.

## Testing the Project

The tests are integration scenarios rather than unit tests: they load a real kernel module and generate real traffic. They should be run carefully, ideally in a dedicated VM.

```bash
# Build, load, and unload
sudo ./tests/test_load.sh

# Observe ICMP traffic
sudo ./tests/test_icmp.sh

# Observe TCP traffic
sudo ./tests/test_tcp.sh

# Observe UDP/DNS traffic
sudo ./tests/test_udp.sh

# Validate filtering criteria
sudo ./tests/test_filtering.sh

# Validate accepted and rejected module parameters
sudo ./tests/test_parameters.sh

# Validate drop decisions
sudo ./tests/test_drop.sh

# Validate non-matching filter criteria
sudo ./tests/test_filter_misses.sh

# Validate parameter boundaries and malformed values
sudo ./tests/test_parameter_boundaries.sh
```

The tests automatically detect the default interface and allow the execution context to be overridden:

```bash
INTERFACE=eth0 LOCAL_IP=192.168.1.20 sudo ./tests/test_icmp.sh
```

### Known Validation Status

The `test_load.sh` scenario verifies the build -> `insmod` -> `rmmod` chain. The traffic scenarios check for a trace in `dmesg`, but their historical filter searches for the `Proto: ...` pattern while the current implementation logs `protocol=<number>`. They are therefore a useful integration foundation, but their assertions must be aligned with the current log format before they can be considered passing automated tests.

## Key Technical Choices

- **Separation of responsibilities**: the hook orchestrates, the parser extracts, the parameter parser validates, and the filter decides.
- **External data validation**: addresses, CIDR prefixes, protocols, and ports are checked before the hook is registered.
- **Care in the kernel path**: `pskb_may_pull()` is used before accessing potentially non-linear headers.
- **Native kernel interfaces**: Netfilter, `module_param`, Kbuild, and kernel logging primitives.
- **Operational reversibility**: the module can be loaded and removed without permanently changing network configuration.

## Limitations and Roadmap

The current scope is intentionally focused:

- IPv4 only, using the `NF_INET_PRE_ROUTING` ingress hook.
- Parameters are interpreted at load time; changing them requires reloading the module.
- No rule persistence, exported counters, or monitoring interface.
- Traffic tests depend on external connectivity and available tools.
- The module must be audited and hardened before use on a critical system.

Natural next steps:

1. Add a synchronized reconfiguration API through `module_param_cb` or configfs.
2. Replace Internet-dependent tests with a local test topology using network namespaces.
3. Add unit tests for the parameter parser and filtering engine.
4. Add per-rule counters exposed through debugfs or sysfs.
5. Extend coverage to IPv6 and additional protocols.
6. Complete the hot-path safety analysis, especially the handling of allocations used for logging ports.

## Arborescence

```text
net_intercept/
├── Makefile
├── net_interception.c       # Netfilter hook and module lifecycle
├── packet_parser.c/.h       # Network header extraction
├── param_parser.c/.h        # Parameter validation and conversion
├── packet_filter.c/.h       # Criteria comparison engine
├── tests/
│   ├── common.sh
│   ├── test_load.sh
│   ├── test_icmp.sh
│   ├── test_tcp.sh
│   ├── test_udp.sh
│   ├── test_filtering.sh
│   ├── test_parameters.sh
│   ├── test_drop.sh
│   ├── test_filter_misses.sh
│   └── test_parameter_boundaries.sh
├── README.md                # Original technical documentation
└── README2.md               # Project presentation and recruiter-facing guide
```

## What This Project Demonstrates

This project demonstrates the ability to:

- work at the boundary between application software and the Linux kernel;
- understand a low-level networking pipeline and its safety constraints;
- decompose a feature into modules with explicit responsibilities;
- design validated configuration exposed through the command line;
- automate reproducible integration checks;
- document technical choices, limitations, and next steps clearly.

## Auteur

**Ivan Peterschmitt**

Project implemented in C for Linux using Netfilter and Kbuild.
