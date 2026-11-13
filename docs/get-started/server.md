# Get a server

Hole needs a {term}`Shadowsocks` server to connect to, and it does not come with one. There are two ways to get one. Pick
the one that fits, then carry the result, a {term}`config` file, over to the computer that will use Hole.

## Route 1: someone gives you a config

If a friend, a relative or an organisation already runs a server for you, ask them for a config for Hole. It is a small
text file whose name ends in `.json`. Hole reads the config formats that other Shadowsocks apps export, whether the file
describes one server or several. A file is imported whole or not at all: if one server in it is refused, for instance
because it names a plugin Hole does not ship, because it lacks a `method` or a `password`, or because its port is not
valid, none of the file's servers are added. The message says what was wrong, and for a plugin it says which plugins
Hole has.

Skip to [Install](install.md).

## Route 2: run your own with Postern

{term}`Postern` is Hole's companion project: a self-hosted portal that sets up Shadowsocks servers, including the
{term}`plugins <SIP003 plugin>` that disguise their traffic. The person running the server adds each person who will
use it, by email address. There is no sign-up form. That person signs in to the portal with a one-time code sent to the
address and downloads a ready-made config.

### What running a server takes

Running a server takes a rented server, a domain name and comfort with a terminal. If you do not have those, ask someone
technical to do this job for you, or take [Route 1](#route-1-someone-gives-you-a-config) and ask them for a config. The
installer and the config are all the other person needs from you.

Postern's own pages are the authority on setting it up, and this guide does not repeat them. To decide whether you want
to, here is what it asks of you:

- **A rented server.** A Linux machine you rent from a hosting company, with Docker and Docker Compose installed, that
  stays on all the time. Python 3.9 or newer must be on it too.
- **A domain name** that you control and can point at the server, and a TLS certificate for it on the server. Postern's
  page shows how to get one.
- **A free Docker Hub account** with an access token, because Postern's base images need a login to download.
- **A way to send email**, because people sign in to the portal with a one-time code sent to their inbox. A mail relay
  service is the quickest start.
- **Comfort with a terminal.** Postern is installed and managed by typing commands, and the operator adds each user with
  a command.

```{admonition} Where to put the server
---
class: tip
---
Rent the server in a country where the websites you want to reach are not blocked. In practice that means outside the
country whose network is filtering your traffic, which is usually not the country of the person who will use Hole.
```

Postern's [Getting started](https://postern.readthedocs.io/en/latest/getting-started.html) page takes you from an empty
server to a working connection. Its [Connecting as a user](https://postern.readthedocs.io/en/latest/connecting.html) page
shows how a person signs in and downloads their config. When you reach the part that sets up a client program, stop: Hole
is the client, and [Connect](connect.md) shows how to import the config into it.

### The plugin in the config

Postern lets the person running the server choose, per connection, between two plugins: {term}`ex-ray`, which a config
names `v2ray-plugin`, and {term}`galoshes`, which also carries UDP. Hole's own install includes both, so you do not
install anything extra on the computer to match either.

```{admonition} Keep galoshes in step with the server
---
class: warning
---
A galoshes client and a galoshes server must be on the same side of the change in how galoshes frames traffic that came
with galoshes v0.4.0, and a newer one is not automatically safer. Hole updates its bundled galoshes together with the
app, so a galoshes connection can stop working after a Hole update if the server has not been upgraded. Upgrade the
server first. Postern's [Connecting as a user](https://postern.readthedocs.io/en/latest/connecting.html) page has the
detail.
```

## What a config looks like

````{dropdown} An example config, with placeholders
This is the shape of a config downloaded from a Postern portal. The values are placeholders.

```json
{
  "servers": [
    {
      "address": "postern.example.com",
      "port": 443,
      "password": "the-password-for-this-connection",
      "method": "chacha20-ietf-poly1305",
      "plugin": "v2ray-plugin",
      "plugin_opts": "tls;path=/t/some-token;host=postern.example.com"
    }
  ],
  "local_port": 1080,
  "local_address": "127.0.0.1"
}
```

Hole imports the entries under `servers` (or under `configs`, which wins if both are present) and ignores the other
top-level fields. A file with no such list is read as one bare server. An entry needs an address, a port, a `method` and
a `password`. It may also carry a `remarks` field, which Hole uses as the server's name; without one, the server is
listed by its address and port.
````

## Getting the config to the user

The config holds the password to the server: anyone who has the file can use the server. Send it to the person it is for
and nobody else, through a private channel such as an end-to-end encrypted messenger. Do not post it anywhere public or
send it in a place others can read. Hole imports the file as it is, so the person using it never has to open it or edit
it.

## Next

[Install Hole](install.md) on the computer that will use it.
