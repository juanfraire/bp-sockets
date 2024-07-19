# BP Sockets

The outcome of STINT 2024 Hackathon. Authored by Scott Burleigh (APL), Felix Walter (D3TN), Olivier De Jonckere (LIRMM), Juan Fraire (Inria), Brian Sipos (APL), Samo Grasic (ICTP), Brian Tomko (NASA), and Ricardo Lent (UH).

## STINT
The Space-Terrestrial Internetworking (STINT) Workshop brings together space networking research and the industrial community's interest in Delay and Disruption-Tolerant Networking (DTN). Sponsored by IPNSIG and D3TN, the 11th edition of STINT was held at the IEEE SMC-IT/SSC conference in Mountain View, California.

## Hackathon
Day 3 of STINT 2024 (July 19th) was dedicated to a hackathon organized by Scott Burleigh. The goal was to tackle a core DTN problem: providing a clean, interoperable API to facilitate application developers in sending data using the Bundle Protocol (BP).

The hackathon focused on implementing such an API based on POSIX sockets. This approach has the central advantage that it requires only minimal modifications in existing applications: only the address family passed to the socket() system call plus the addresses themselves (that are replaced with DTN endpoint identifiers) would need to be adapted in existing applications otherwise using datagram (e.g., UDP) sockets.

### Architecture
The resulting “BP Sockets” interface integrates with bundle protocol stacks in user space. Netlink IPC (Inter-Process Communication) coordinates kernel and user space interactions. The main elements of the architecture are described below.

![Architecture](img-architecture.png)

#### BP Sockets Application
The user application creates a socket with a newly introduced address family 28, with the datagram (DGRAM) type and protocol number 0. The destination EID is provided via the sockaddr parameter of the sendto() function, and the Application Data Unit (ADU) to be conveyed via BP is provided in the message field.

#### BP Sockets Kernel Module
A kernel module processes BP Sockets calls. This module uses Netlink to deliver the bundle payload and related metadata to the BP Sockets Daemon. Netlink is a communication protocol between the Linux kernel and userspace processes designed for asynchronous message passing. 

#### BP Sockets Daemon 
Upon receiving a message, the BP Sockets Daemon in userspace retrieves the EID and the ADU, creates a bundle with ION, and sends it to the peer. In our case, the destination was running µD3TN on a second virtual machine (VM). This way, we demonstrated interoperability between µD3TN and ION using the BP Sockets interface.  Note that the BP Sockets Daemon is modular and not locked to ION; it could easily be adapted to another Bundle Protocol implementation. 

### Organization 
The work was organized into teams:
- Team 1: Infrastructure and Applications. Deployed µD3TN and ION BP nodes on two virtual machines running Debian 12 with Linux kernel version 6.1.0-22-amd64, using the TCPCLv3 convergence layer protocol to send and receive bundles.
Two members: Juan Fraire (Inria) and Samo Grasic (ICTP).

- Team 2: BP Sockets Daemon. Created the BP Sockets Daemon (deployed in userspace) to manage socket states, handle IPC with the BP Sockets Kernel Module plug-in, and use ION to send the created bundles. Adapted from Mark O’Neill’s Secure Sockets API (SSA), source code at https://github.com/markoneill/ssa-daemon.
Two members: Scott Burleigh (APL) and Felix Walter (D3TN).

- Team 3: BP Sockets Plug-in Kernel Module. Implemented a custom protocol for BP Sockets Kernel Module (deployed in kernel space) inspired by Mark O'Neill's Secure Socket API (SSA), available in this repository: https://github.com/markoneill/ssa.
Four members: Olivier De Jonckere (Montpellier University), Brian Sipos (APL), Ricardo Lent (UH) and Brian Tomko (NASA).

### Outcome
During the hackathon, we developed a proof-of-concept for BP Sockets. It was demonstrated by transmitting bundles from a minimal user space application through the Linux kernel and ION to µD3TN using BP Sockets. The screenshot below shows the µD3TN log (the receiving BP node) on the top, the BP Sockets App sender on the bottom left, and the BP App receiver output on the bottom right. 

![Screenshot](img-screenshot.png)

### Code
The resulting BP Socket code developed during the hackathon is publicly available in this GitHub repository: https://github.com/juanfraire/bp-sockets. Here is a brief explanation of the components:

#### BP Sockets Application (`bp-user-app-with-sock.c`)
This application handles socket operations for sending DTN data. The source code file for the test application is located in the root directory. 
`bp-user-app-with-sock.c`: A test application to send custom protocol messages. The main sending process is a standard (simple) socket operation, as shown below.
```
#define AF_BP 28
// [...]
sockfd = socket(AF_BP, SOCK_DGRAM, 0);
// [...]
struct sockaddr eID;
// [...]
ret = sendto(sockfd, msg, strlen(msg)+1, 0, &eID, sizeof(eID));
// [...]
close(sockfd);
```

To deploy the socket app, use the following commands (the kernel module must be deployed, and the socket daemon should be initialized):
- `gcc -o bp-user-app-with-sock bp-user-app-with-sock.c`
- `sudo ./bp-user-app-with-sock`

#### BP Sockets Kernel Module (`bp-sock` directory)
This kernel module supports BP socket operations and communicates with the BP Sockets Daemon. It:
- Implements socket functions (open, sendto, close).
- Opens an IPC connection to the BP sockets daemon.
- Sends messages to the daemon to handle text transmission.

The source code files are located in the `bp-sock` directory. They implement the BP Sockets kernel module. The most relevant files include:
- `bpsock.c`: Core files for implementing the custom protocol for BP sockets. Implements new socket operations (open, sendto, close).
    - Defines `CUSTOM_PROTO_FAMILY` with a value of `28`, representing the custom protocol family.
    - `struct proto` and `struct proto_ops` are used to define the custom protocol operations and socket properties.
    - Main Operations:
        - `custom_create`: Initializes and allocates resources for a new socket.
        - Sets the socket operations.
        - Allocates a new socket (`sk_alloc`).
        - Initializes socket data (`sock_init_data`).
        - `custom_release`: Cleans up and releases resources when a socket is closed.
        - Puts the socket (`sock_put`).
        - `custom_sendmsg`: Handles sending messages through the custom protocol.
        - Allocates memory for the data to be sent.
        - Copies data from user space to kernel space (`copy_from_iter`).
- `netlink.c`: Handle IPC using Netlink.

To deploy the kernel module, use the following commands:
- `apt install linux-headers-$(uname -r)`
- build with `make`
- `insmod bp.ko`

#### BP Sockets Daemon (`bp-daemon` directory)
This daemon manages the state of BP sockets and handles communication with the BP sockets kernel module and the DTN protocol stack (ION, in this case). Specifically, it:
- Opens an IPC connection with the BP sockets kernel module.
- Manages socket state objects.
- Receives messages from the BP sockets plug-in to send text using ION.

The source code files are located in the `bp-daemon` directory. They implement the BP Sockets Daemon. The most relevant files include:
- `daemon.c`: Core functions of the BP sockets daemon.
- `main.c`: Contains the main entry point for the daemon.
- `netlink.c`: Handle IPC using Netlink.
- `hashmap.c`, `hashmap_str.c`: Implement hash maps to manage socket states.
- `log.c`: Logging functionality.

To deploy the B daemon, use the following commands:
- `apt install pkg-config libnl-genl-3-dev libevent-dev`
- build with `make`
- `ionstart -I host1.rc`
- `run ./bp_daemon`

## Next Steps
The following steps identified at the STINT 2024 hackathon are:
- Design and implement the receiver data flow in BP Sockets. We have only implemented and tested the transmission part.
- Extend the BP Sockets Daemon to support other DTN stacks besides ION (e.g., µD3TN).
- Expose more protocol versions (bpv6, bpv7) and options (QoS, custody transfer, reporting) as optional parameters via the socket options (sockopt) interface.
- Explore a proper binding between SOCK_DGRAM and SOCK_STREAM socket models and expected DTN data handling modes.
- Clean up and stabilize the API and the internal message types and infrastructure.
- Explore the possible performance and memory bottlenecks of the socket interface.

## References
- Useful and related links:
- SSA: https://github.com/markoneill/ssa 
- SSA Daemon: https://github.com/markoneill/ssa-daemon 
- Unified API for DTN  (by University of Bologna): https://gitlab.com/dtnsuite/unified_api/-/tree/master?ref_type=heads 


  

 





