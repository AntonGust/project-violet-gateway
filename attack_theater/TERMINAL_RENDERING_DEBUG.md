# Attack Theater — Terminal Rendering Debug Notes

## The Problem

xterm.js replay of Cowrie TTY sessions shows garbled lines where prompt text
merges with command output or previous line content. Example artifacts:

```
root@wp-prod-01:~# sh root@172.10.0.11 -p 222       ← missing first 's' and last '2'
2root@wp-prod-01:~# ssh: connect to host ...         ← '2' leftover + prompt + error
s
hs h271.01..011ssh: connect to host ...
root@wp-prod-01:~# shs
 712.0|                                              ← cursor
```

Expected clean output (verified with pyte virtual terminal emulator):
```
root@wp-prod-01:~# ssh root@172.10.0.11 -p 2222
ssh: connect to host 172.10.0.11 port 22: Connection refused
root@wp-prod-01:~# ssh 172.10.0
```

## TTY File Under Test

`demo/cowrie_logs/hop1/lib/cowrie/tty/8e144b92a86e12a9683b04e866ee0b92ac523702bda5f524eb9c1fa82884d7ae`
- 80 KB, ~900s, 2283 data frames
- Real human attacker session (typos, backspaces, Docker commands, nested SSH)

## Confirmed Facts About the Stream

1. **Zero bare `\r` bytes** in any OUTPUT frame. The original "lone \\r" diagnosis was wrong.
2. **Only 4 escape sequences** appear in OUTPUT frames:
   - `\x1b[1D` — cursor left 1 (176×, used for backspace)
   - `\x1b[1P` — DCH delete char at cursor (176×, used for backspace)
   - `\x1b[4h` — IRM set insert mode (55×, before every prompt)
   - `\x1b[4l` — IRM clear (54×, after Enter/before command output)
3. No cursor-up, no clear-screen, no other positioning sequences.
4. Frame 1 of session sets `\x1b[4h` immediately (IRM active from start).
5. Frame structure: `op=3 dir=2` = OUTPUT; `op=3 dir=1` = INPUT (skipped by tty_reader).
6. op=1 / op=2 are session start/end markers with empty payloads — no window size recorded.
7. The cat `.bash_history` output (frames 1621–1653) precedes the SSH section and
   renders correctly — so the terminal was clean before the garbled section.
8. **pyte simulation** with `strip_irm + \n→\r\n` produces correct output (verified).
   The bug is xterm.js-specific.

## Key Frame Sequence (SSH attempt section)

```
[1617] OUT  b'cat .bash_history '       ← pasted command echo
[1618] IN   b'\r'                       ← Enter (skipped)
[1619] OUT  b'\n'                       ← newline after Enter
[1620] OUT  b'\x1b[4l'                 ← clear IRM
[1621-1653] OUT  <bash_history lines>   ← each ends with \n
[1653] OUT  b'ssh root@172.10.0.11 -p 2222\n'   ← last history line
[1654] OUT  b'\x1b[4h'                 ← set IRM (before prompt)
[1655] OUT  b'root@wp-prod-01:~# '     ← prompt
[1656] IN   b'ssh root@172.10.0.11 -p 2222\r'   ← attacker input (skipped)
[1657-1684] OUT  b's' b's' b'h' ...   ← char-by-char echo of typing
[1685] OUT  b'\n'                       ← Enter pressed
[1686] OUT  b'\x1b[4l'                 ← clear IRM
[1687] OUT  b'ssh: connect to host 172.10.0.11 port 22: Connection refused\n'
[1688] OUT  b'\x1b[4h'                 ← set IRM (before next prompt)
[1689] OUT  b'root@wp-prod-01:~# '     ← next prompt
[1690-1691] IN  b'\x1bOA'             ← UP arrow × 2 (no echo output = Cowrie ignores history)
[1692-...] IN+OUT  char by char typing of second attempt + backspaces
```

## Fixes Attempted — All Failed

### Attempt 1 — normalizeEol (WRONG, made things worse)
Added a function to convert lone `\r` → `\r\n`. Caused NEW artifacts (`cd /homehroot@...`).
**Root cause of wrongness:** there are ZERO lone `\r` bytes in the stream.
**Status: Reverted.**

### Attempt 2 — stripIrm
Added `stripIrm()` to remove `\x1b[4h` and `\x1b[4l` from frames.
Hypothesis: IRM causes prompt chars to INSERT into existing line content.
Result: Changed the garbling pattern but did not fix it.
**Status: Still in place (probably harmless but not the root fix).**

### Attempt 3 — term.write() callback
Changed `drainFrames()` to pass itself as callback to `term.write()`:
```javascript
term.write(data, drainFrames);  // was: term.write(data); drainFrames();
```
Hypothesis: async write buffer causes out-of-order processing.
Result: No visible change to garbling.
**Status: Still in place (correct practice but not the root fix).**

### Attempt 4 — explicit \n→\r\n + convertEol:false
Added `\n` → `\r\n` expansion inside `normalizeFrame()`, set `convertEol: false`.
Hypothesis: xterm.js convertEol interacts badly with IRM state.
Result: No change. Still garbled.
**Status: Still in place.**

## Current State of app.js

`normalizeFrame()` function (lines ~137–170):
- Strips `\x1b[4h` and `\x1b[4l`
- Expands bare `\n` → `\r\n`

Terminal config: `convertEol: false`
drainFrames: uses `term.write(data, drainFrames)` callback form.

## Hypotheses NOT Yet Tested

1. **Terminal width mismatch** — Original session may have been recorded at a width other
   than 80 cols. xterm.js defaults to 80 cols with no fitAddon. If the recording was at
   e.g. 220 cols, line wrapping and cursor positions would differ. The TTY file has NO
   window size frames (op=1/2 are empty), so we cannot know the original width.
   **Test:** Try adding FitAddon and calling `fitAddon.fit()`, or hardcode `cols: 220`.

2. **xterm.js version bug** — The bundled xterm.js (283KB minified) may have a specific
   bug with DCH (`\x1b[1P`) or with cursor positioning that doesn't reproduce in pyte.
   **Test:** Replace with a known-good version (e.g. xterm.js 5.3.0 from CDN).

3. **Binary frame corruption** — Frames 90, 118, 185 contain raw ELF binary data
   (from `cat redtail.arm7`). Binary bytes include 0x0E (SO — shift out / alt charset),
   0x0F (SI — shift in), and other control chars. These could put xterm.js into an
   alternate character set mode that causes misaligned rendering.
   pyte may handle these more gracefully than xterm.js.
   **Test:** Add a filter to strip all non-printable bytes outside of known escape
   sequences from frames, OR specifically reset character set after binary frames.

4. **SO/SI character set corruption** — Related to #3. xterm.js supports G0/G1 character
   set switching. A stray `\x0E` (SO) switches to G1 (line-drawing charset), causing
   all subsequent characters to render as box-drawing glyphs or misaligned glyphs.
   **Test:** Inject `\x0F` (SI — return to G0) at the start of every frame, or filter
   all `\x0E`/`\x0F` bytes from the stream.
   **This is the highest-probability untested hypothesis.**

## Recommended Next Step

Test hypothesis #4 first (SO/SI charset corruption):

```javascript
// In normalizeFrame(), also strip SO (0x0E) and SI (0x0F)
// and inject a SI reset at start of every frame for safety:
function normalizeFrame(u8) {
  const out = [0x0F];  // SI: ensure G0 (standard charset) at start of each frame
  let i = 0;
  while (i < u8.length) {
    // strip IRM sequences
    if (i + 3 < u8.length && u8[i] === 0x1B && u8[i+1] === 0x5B && u8[i+2] === 0x34
        && (u8[i+3] === 0x68 || u8[i+3] === 0x6C)) { i += 4; continue; }
    // strip SO / SI
    if (u8[i] === 0x0E || u8[i] === 0x0F) { i++; continue; }
    // expand LF → CRLF
    if (u8[i] === 0x0A) out.push(0x0D);
    out.push(u8[i++]);
  }
  return new Uint8Array(out);
}
```

If that doesn't work, test hypothesis #1 (terminal width): try setting `cols: 220`
in the Terminal constructor to match a wide recording terminal.
