# Tunnels through Cloudflare compared with direct tunnels

In November 2026 six tunnels to one server were probed from a residential MGTS connection every five minutes for 42
hours. The two tunnels that went straight to the server passed every probe. The four that went through Cloudflare did
not work as tunnels: with {term}`ECH` almost no connection carried anything, and without it a connection carried its
first exchange and then stalled. The block on TLS handshakes to the server's provider, seen from the same connection in
[June 2026](2026-06-tls-handshake-block.md), was no longer there.

## Setup

:Date: 19 and 20 November 2026
:Client: The project's test machine in Russia (the client of the June 2026 report), Windows 11. Hole was not used: the
tunnels were `sslocal` from shadowsocks-rust 1.25.0 with {term}`ex-ray` 0.3.1 and {term}`galoshes` 0.4.1, each
listening on a local port.
:Client network: MGTS, residential
:Server: Shadowsocks with ex-ray and with galoshes, behind a web server with TLS, hosted at LeaseWeb within
85.17.0.0/16. It answered under two names: one pointing straight at it, one proxied by Cloudflare with ECH on.
:Tunnels: ex-ray and galoshes, each three ways: straight to the server, through Cloudflare with `ech=auto`, and through
Cloudflare with `ech=never`. The Cloudflare configs named Cloudflare's address and its {term}`DoH` resolver by IP.
:Control: A machine outside Russia with the same programs and configs, for the tests of 19 November before the probes
began

## Timeline

All times are UTC.

1. 19 November, 00:47 to 00:57. TLS handshakes from the client to the server and to every host in the four address
   ranges of the June report.
1. 01:20 to 01:45. Each of the six tunnels is tried twice, from the client and from the control. Plain HTTPS downloads
   from the server, with no tunnel, straight and through Cloudflare.
1. 01:41. The probes begin: through each tunnel, a small page and a 100 KB download every five minutes and a 2 MB
   download every hour.
1. 20 November, 19:36. The probes are stopped after 298 rounds. Three days had been planned.

## Measurements

### The address ranges of the June report

From the client, TLS handshakes to the server completed on three ports, with the server's own name, an unrelated name
and no {term}`SNI` extension. A 300 MB download over TLS ran for 100 seconds without interruption.

In June every live host in three /24 ranges of LeaseWeb and one of OVH failed the TLS handshake from this connection.
This time the client completed the handshake with nearly every host the control did:

| Range                  | Hosts that completed from the control | Of those, also from the client |
| ---------------------- | ------------------------------------- | ------------------------------ |
| LeaseWeb, first /24    | 26                                    | 16                             |
| LeaseWeb, second /24   | 89                                    | 86                             |
| LeaseWeb, third /24    | 87                                    | 84                             |
| OVH in Canada, one /24 | 22                                    | 22                             |

The ten missing hosts of the first range did not accept a TCP connection from the client within three seconds.

### One request through each tunnel

A small page, then a 2 MB download, on 19 November at 01:27 and again at 01:35.

| Tunnel                            | From the client                                                                | From the control |
| --------------------------------- | ------------------------------------------------------------------------------ | ---------------- |
| ex-ray, straight to the server    | Works: 2 MB in 0.5 s                                                           | Works            |
| galoshes, straight to the server  | Works: 2 MB in 0.6 s                                                           | Works            |
| ex-ray, Cloudflare, `ech=auto`    | Nothing passes; the request times out after 40 s                               | Works            |
| galoshes, Cloudflare, `ech=auto`  | Nothing passes; galoshes logs "transport silent across the keepalive deadline" | Works            |
| ex-ray, Cloudflare, `ech=never`   | The small page arrives; the download gets nothing and ends after 20.7 s        | Not run          |
| galoshes, Cloudflare, `ech=never` | 5.5 KB of the 2 MB arrive, then nothing for 40 s                               | Not run          |

### Plain HTTPS through Cloudflare, with no tunnel

A 1 MB file from the same server, requested from the client:

| Request                                                                      | Result                                                                    |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| Through Cloudflare, the server's name in the SNI extension, no ECH (3 tries) | 17,770, 16,733 and 17,770 bytes, then nothing; reset after 23.5 to 24.9 s |
| Straight from the server                                                     | 1,048,576 bytes in 0.47 s                                                 |
| 1 MB from Cloudflare's own speed-test site                                   | 1,000,000 bytes in 0.14 s                                                 |
| The same file through Cloudflare, from the control                           | 1,048,576 bytes in 0.44 s                                                 |

A TLS connection to the server's Cloudflare address, held open with one small request every five seconds, went silent
after 5.5 KB under the server's name. Under the name of Cloudflare's own site, the same address answered for the whole
60 seconds.

### 42 hours of probes

A download counts as complete only if every byte arrived. A probe with no tunnel succeeded in all 298 rounds.

| Tunnel                            | Small page | 100 KB     | 2 MB     |
| --------------------------------- | ---------- | ---------- | -------- |
| ex-ray, straight to the server    | 298 of 298 | 298 of 298 | 25 of 25 |
| galoshes, straight to the server  | 298 of 298 | 298 of 298 | 25 of 25 |
| ex-ray, Cloudflare, `ech=auto`    | 0 of 298   | 0 of 298   | 0 of 25  |
| ex-ray, Cloudflare, `ech=never`   | 297 of 298 | 0 of 298   | 0 of 25  |
| galoshes, Cloudflare, `ech=auto`  | 76 of 298  | 77 of 298  | 6 of 25  |
| galoshes, Cloudflare, `ech=never` | 97 of 298  | 45 of 298  | 4 of 25  |

- **Straight to the server.** galoshes held one connection for the whole 42 hours and never reconnected.
- **ex-ray through Cloudflare with ECH.** All 621 probes timed out.
- **ex-ray through Cloudflare without ECH.** The small page, 192 bytes, arrived in 2.3 seconds, against 0.34 seconds
  straight to the server. No download completed. Eight of the 2 MB downloads received between 1.4 and 8.8 KB.
- **galoshes through Cloudflare with ECH.** galoshes made 2,119 connections. 2,113 of them never carried anything, and
  its {term}`keepalive` replaced each about 55 seconds after it was made. Four lasted 27, 37, 82 and 459 minutes, and
  the probes that succeeded fell inside those: every probe from 07:33 to 08:50 on the 19th and from 08:22 to 15:46 on
  the 20th, at the speed of a working tunnel (2 MB in 3.7 seconds).
- **galoshes through Cloudflare without ECH.** 2,011 connections. 1,994 carried something first and then went silent,
  and the keepalive replaced each about 71 seconds after it was made. One lasted 361 minutes, and every probe from
  23:45 on the 19th to 05:47 on the 20th succeeded.

## What the measurements suggest

- The block of June 2026 on the provider's address ranges was not in force from this connection in November.
- The connection to Cloudflare is interfered with one connection at a time. Of about 4,100 galoshes connections
  through Cloudflare, five were left alone, and each of those then carried traffic at full speed for between 27 minutes
  and more than seven hours. The logs do not show why those five passed.
- The interference follows the name the connection announces. Cloudflare's own name on the same address was not cut,
  and the server's name was, after about 17 KB.
- With ECH, where the network cannot read the server's name, almost nothing passed at all.
- This is the failure of the [August 2026 report](2026-08-cdn-fronted-server.md), reproduced: a first exchange passes,
  so Hole's start-time {term}`self-test` can pass, and then the tunnel carries nothing.
- galoshes got hours of service out of the five connections because it keeps one connection and puts every stream on
  it. ex-ray opens a connection for each request and got none.

## Limitations of these measurements

One client on one network. No packets were captured during the 42 hours, so the logs do not show who cut a connection,
or how a surviving connection differed from the others. Other CDNs, a paid Cloudflare plan and `ech=always` were not
tried.
