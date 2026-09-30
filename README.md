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
- `nothing from <server> for X s, still sending` when the server goes quiet mid-zone, and `DISCONNECT, ...` if the game then gives up.
- `local port N is taken`: another client on this PC holds the port, the game retries at +256. A different port than on the previous zone is worth noting.
- `receive error 10054`: an ICMP "port unreachable" came back for something the game sent.
- `server assigned slot N`: the server picked the port. If this changes while in game, the next zone uses a different port.

Times are local. The first line of each log gives the UTC offset, since server logs are usually in UTC.

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
