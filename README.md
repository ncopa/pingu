pingu
=====

Pingu is a daemon that takes care of policy routing and fail-over in
multi ISP setups.

Features
--------
- Support for DHCP
- Support for PPP
- ISP failover
- Load-balancing (nexthop)
- Optional route rule based on fwmark
- run script when ISP goes up/down


Build requirements
------------------
- libev 3 or newer (http://software.schmorp.de/pkg/libev.html)
- asciidoc (optional for creating man pages)

To build pingu without man pages run configure --disable-doc


