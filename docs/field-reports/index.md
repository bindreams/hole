# Field reports

Hole is built for networks that interfere with traffic, and it has been tried on some of them: from Russia, on a phone
hotspot, on test boxes. These pages are case studies of what those networks did and what the technique did about it. They
are about the environment and the technique, not about bugs in a release.

Each page keeps three kinds of statement apart:

- **Observed**: what a log, a capture or a probe showed on a particular machine, said as such.
- **What the code does**: what Hole or its plugin does with that input, checked against the source.
- **Hypothesis**: a reading that fits the observations and has not been tested. It is labelled, and where a test would
  settle it, the page says which.

Nothing here names a person, a machine or a server. "A client in Russia" and "a test box" stand for real ones.

## The cases

- [A CDN address that never answers](russia-ech-investigation.md): a client in Russia whose connections to a
  CDN-fronted server never completed. The case is open: the reading that a censor was at work was never tested.
- [When the server is fine but the handshake dies](range-blocked-hosts.md): a network that lets TCP through and resets
  the TLS handshake for whole ranges of hosting providers, and how to tell it from a bad password.
- [ECH in practice](ech-in-practice.md): hiding the server's name with {term}`ECH`, the lookup that can give it away,
  and what happens when the key rotates.

## What to do with them

[Recommendations for hostile networks](hostile-networks.md) starts from how to tell three failures apart, then lists
what to set and what to avoid, each with the case it comes from.
