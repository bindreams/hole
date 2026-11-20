# Network interference blocking TLS handshakes

In June 2026 a beta tester on a residential MGTS connection in Russia could not connect to a server hosted at LeaseWeb
in the Netherlands. The server was healthy. Tests from the tester's machine showed that TCP connections to it were
accepted and every TLS handshake on top of them failed, for every host in the server's neighbouring address ranges as
well.

## Setup

:Date: June 2026
:Client: Windows 11 with Hole, on the project's test machine in Russia
:Client network: MGTS, residential
:Server: Shadowsocks with {term}`galoshes` over WebSocket and TLS, hosted at LeaseWeb in the Netherlands
:Tests: Run on the client by a maintainer, over SSH
:Control: The same server, reached from a network that does not interfere

## Timeline

1. Connect fails. Hole reports that its DNS {term}`self-test` timed out.
1. **Test** on the server reports "Server rejected the connection (wrong password, cipher, or plugin config)."
1. From the control network the server is healthy: TLS to it is fast and its web portal answers.
1. 21 June: the tests in the next section are run on the client.
1. 25 June: Hole is changed to recognise this failure and report it as a network block
   ([the reachability check](../../how-it-works/reachability-check.md)).
1. By August 2026 the server is behind Cloudflare.

## Measurements

All tests ran on the client.

| Target                                                                         | TCP connect              | TLS handshake |
| ------------------------------------------------------------------------------ | ------------------------ | ------------- |
| The server, ports 443 and 80                                                   | Connected in about 50 ms | Failed        |
| The server, with an unrelated name in the {term}`SNI` extension                | Connected                | Failed        |
| The server, addressed by IP instead of by name                                 | Connected                | Failed        |
| Every live host found in three /24 ranges of LeaseWeb, all within 85.17.0.0/16 | Connected                | Failed        |
| Every live host found in one /24 range of OVH in Canada, within 51.79.0.0/16   | Connected                | Failed        |
| Hosts at Hetzner in Germany and Finland, within 88.99.0.0/16 and 65.108.0.0/16 | Connected                | Succeeded     |
| Hosts at DigitalOcean in the United States, within 104.248.0.0/16              | Connected                | Succeeded     |
| 1.1.1.1 and example.com                                                        | Connected                | Succeeded     |

A traceroute reached the server in 47 ms, through Russian hops.

A failed handshake means the {term}`ClientHello` was reset or dropped; the tests did not record which. They were TLS
handshakes only, so they do not show whether other traffic to the same addresses passes.

## Conclusions

The server was reachable and its route was intact: TCP connected in 50 ms. The server's name was not the trigger: the
handshake failed the same way with an unrelated name and with the bare IP address. The server was not singled out:
every live host found in four address ranges of two hosting providers failed with it, while hosts at two other
providers completed the handshake.

A block of this shape, applied to whole address ranges of hosting providers, is what the {term}`TSPU` equipment at
Russian providers can do. The measurements do not show who applied it or how the ranges were chosen.

A server in these LeaseWeb and OVH ranges cannot be reached over TLS from this network, and another address in the same
ranges will not help. The tests covered three /24 ranges of LeaseWeb and one of OVH, not the whole address space of
either. [Recommendations for hostile networks](../hostile-networks.md#put-the-server-where-the-network-can-reach-it)
covers moving the server.

Waiting longer does not help. Hole's self-test timed out because the handshake never completed, and no timeout turns a
blocked handshake into an answer.
