# my-torrent

A simple BitTorrent client written in Zig ⚡️

## Supported Specifications

- [The BitTorrent Protocol Specification — bep 3](https://www.bittorrent.org/beps/bep_0003.html)
- [UDP Tracker Protocol — bep 15](https://www.bittorrent.org/beps/bep_0015.html)
- [Tracker Returns Compact Peer Lists — bep 23](https://www.bittorrent.org/beps/bep_0023.html)

## Build & Run

### Requirements

- Zig (version 0.13.0)

### Instructions

To build & run for **Debuging**:

`zig build run -- info -f ./samples/sample.torrent`

To build for **Release**:

`zig build -Doptimize=ReleaseFast`

and then run from `./zig-out/bin/my-torrent`.

## Contribute

I'll be happy to review your PR 😎
