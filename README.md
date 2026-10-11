# zonetrace

Ashita v4 POL plugin for chasing black screens and disconnects on zone. It records which local UDP port the game uses for each zone connection and whether the server answers. Nothing of the traffic itself is logged, only addresses, counts and timings, so the log is safe to hand to a server admin.

## What it shows

The game opens a new UDP socket for every zone. It asks PlayOnline (polcore) for the local port, binds it, and repeats its zone-in request until the server answers. A black screen is that request never being answered.

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

The lines that matter when something goes wrong:

- `BLACK SCREEN, <server> never answered N zone-in requests in X s` when a socket is closed without a single answer.
- `BLACK SCREEN so far, ...` when a zone-in is still unanswered after 10 s, written while waiting so it survives the client being killed.
- `datagram from <address> while talking to <server>`: something other than the zone server reached the socket, typically the previous zone server still sending.
- `the game has not sent anything for X s`: the client itself stalled or gave up, as opposed to the server going quiet.
- `zone-in answered 15 s ago but no character loaded`: answers arrive but the game cannot use them, usually a key mismatch. Compare the `key` fingerprint with the server's.
- `nothing from <server> for X s, still sending` when the server goes quiet mid-zone, and `DISCONNECT, ...` if the game then gives up.
- `local port N is taken`: another client on this PC holds the port, the game retries at +256.
- `LOCAL PORT CHANGED A -> B since the previous zone`: the game came back from a different port than it left with. A server that ties the session to the client's address will not recognise it.
- `char   Name (charid N) in zone Z`: written once per zone, to match this log against the server's.
- `receive error 10054`: an ICMP "port unreachable" came back for something the game sent.
- `server assigned slot N`: the server picked the port. If this changes while in game, the next zone uses a different port.
- `session key value fingerprint XXXXXXXX`: a hash of the 16-byte value the game builds its zone cipher key from, logged whenever PlayOnline hands out a new one. The game takes the value current at character select. The value itself is never logged.

- `zone key counter XXXXXXXX (+N)`: the other half of the zone cipher key. The lobby code adds 1 per lobby request and 1 per success reply, 1 per error reply only on the name check, world list, rename and GM move requests, then 2 per zone. The server cannot see it and keeps its own copy, so any lobby step it did not account for gives the game a key it cannot decrypt with. The counter is not secret: on servers that hand out no key value the whole key is constants plus this counter.

- `recv   dropped N wrong key, N old datagram, ... (server sequence XXXX accepted, server acked XXXX, game at XXXX, state N)`: the game threw away packets the server sent. The game counts these itself, by reason:
  - `wrong key`: the payload did not check out after decrypting, the server's key differs from the game's.
  - `malformed`: bad size or the payload did not decompress.
  - `old datagram`: the server's datagram sequence was not newer than the last one the game accepted (only checked in state 3).
  - `empty packet`, `old sub-packet`: a sub-packet of size 0, or one whose sync is not newer than the last accepted datagram.
  - `no handler`: a packet the game does not handle. Common in normal play, so it never triggers a line by itself.

  A stream of wrong-key or old-datagram drops while stuck on the black screen names the cause. The `char` warning for a zone-in that never loads is followed by `recv   drops so far:` with the totals for that zone.

For the counter, the server's value at character select is bytes 16..19 of `accounts_sessions.session_key` (little-endian), and the map adds 2 per zone. On LSB with the stock loader a clean login reads `AD5DE058` on both sides (lobby seed `AD5DE04F` plus 9 steps); after a lobby error and a retry the client is higher.

To compare on the server, hash the first 16 bytes of the character's `accounts_sessions.session_key` the same way (FNV-1a, 32-bit):

```python
h = 2166136261
for b in session_key[:16]:
    h = ((h ^ b) * 16777619) & 0xFFFFFFFF
print(f"{h:08X}")
```

Times are local. The first line of each log states the time zone and its UTC offset, since server logs are usually in UTC.

## Use

Copy `zonetrace.dll` into Ashita's `polplugins` folder and enable it in the boot config:

```ini
[ashita.polplugins]
zonetrace = 1
```

One log per game process in `polplugins\logs\zonetrace_<date>_<time>_<pid>.log`. In game, `/zonetrace mark <text>` writes a labelled line, handy right after a black screen.

Do not load it together with polsniff: both hook the same places, and whichever loads second finds nothing to hook. zonetrace says so in its log and stops trying after ten seconds.

## Build

`build.bat [outdir]` loads vcvars32 and builds with CMake/Ninja. Needs `ASHITA4_SDK_PATH` (defaults to `E:\Ashita-v4beta\plugins\sdk`). Running clients hold the dll open, so pass a staging folder while they are up.

## Notes

- The polcore hook is found by signature and matches the current retail `polcore.dll`. If a client update moves it, the socket lines still work; only the `port` lines go missing.
- The game's sockets are hooked through FFXiMain's import table, so only the game's own traffic is seen.
