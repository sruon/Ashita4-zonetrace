# zonetrace

Ashita v4 POL plugin to troubleshoot black screens and disconnects when zoning. It logs the local UDP port the game uses for each zone, whether the server answers, the zone key and the packets the game drops. Packet contents and key material are never logged.

## Log

The game opens a new UDP socket for every zone, asks polcore for the local port, binds it and repeats its zone-in request until the server answers.

```
23:01:35.838 port   hooked polcore.dll: game index -1, port 54090 (1 getter slots, setter ok)
23:01:36.216 port   server assigned slot 2, the game will bind 54091 from its next socket on
23:01:51.428 port   game asks for its port: 54091 (game index -1, server asked for 54091)
23:01:51.428 socket local port 54091 is taken (error 10048)
23:01:51.428 socket bound local port 54347
23:01:51.429 socket port 54347 connecting to 203.0.113.10:54230
23:01:51.702 socket port 54347: zone-in answered after 0.3 s and 1 requests
23:34:31.811 socket closed port 54347 to 203.0.113.10:54230 after 1960.4 s, sent 4893, received 4889
```

Lines to look for:

- `BLACK SCREEN, <server> never answered N zone-in requests in X s`: socket closed without a single answer.
- `BLACK SCREEN so far, ...`: zone-in still unanswered after 10 s. Written while waiting, so it is there even if the client gets killed.
- `zone-in answered 15 s ago but no character loaded`: answers arrive but the game can't use them. Followed by `recv   drops so far:`.
- `datagram from <address> while talking to <server>`: something other than the zone server reached the socket.
- `the game has not sent anything for X s`: the client stalled, not the server.
- `nothing from <server> for X s, still sending`, then `DISCONNECT, ...` if the game gives up.
- `local port N is taken`: another client on this PC holds the port, the game retries at +256.
- `LOCAL PORT CHANGED A -> B since the previous zone`: the game came back from a different port.
- `server assigned slot N`: the server picked the port.
- `receive error 10054`: ICMP port unreachable for something the game sent.
- `char   Name (charid N) in zone Z`: once per zone, to match against the server logs.
- `session key value fingerprint XXXXXXXX`: FNV-1a of the 16-byte value the zone key is built from. Logged when PlayOnline hands out a new one.
- `zone key counter XXXXXXXX (+N)`: the counter hashed with that value into the zone key. Steps during the lobby, then +2 per zone.
- `recv   dropped ...`: packets the game threw away, counted by the game itself:
  - `wrong key`: payload does not check out after decrypting, the server's key differs.
  - `malformed`: bad size or does not decompress.
  - `old datagram`: sequence not newer than the last accepted one (only checked in state 3).
  - `empty packet`, `old sub-packet`: sub-packet of size 0, or sync not newer than the last accepted datagram.
  - `no handler`: packet the game does not handle. Common in normal play, never logged on its own.

Times are local, the first line of each log has the UTC offset.

## Comparing with an LSB server

LSB logs the same numbers:

- xi_connect at character select: `data_session: ... key value XXXXXXXX, key counter XXXXXXXX`. Matches `session key value fingerprint` and the `zone key counter` logged when the game connects to its first zone.
- xi_map on every zone change: `map_session: key counter for <name> (charid N) is now XXXXXXXX`. Matches the next `zone key counter`.

If either differs, the server and the game hold different keys: the zone-in is answered but the character never loads.

## Use

Copy `zonetrace.dll` into Ashita's `polplugins` folder and enable it in the boot config:

```ini
[ashita.polplugins]
zonetrace = 1
```

Logs go to `polplugins\logs\zonetrace_<date>_<time>_<pid>.log`, one per game process. `/zonetrace mark <text>` adds a labelled line.

## Build

From an x86 Native Tools prompt, with `ASHITA4_SDK_PATH` pointing at Ashita's `plugins\sdk`:

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DZONETRACE_OUTPUT_DIR=<folder>
cmake --build build
```

`ZONETRACE_OUTPUT_DIR` defaults to `E:/Ashita-v4beta/polplugins`. A running client holds the dll open, so build somewhere else while one is up.

## Notes

- Everything is found by signature in the retail `polcore.dll` and `FFXiMain.dll`. If an update moves something, that part says so in the log and the rest keeps working.
- Sockets are hooked through FFXiMain's import table, so only the game's own traffic is seen.
