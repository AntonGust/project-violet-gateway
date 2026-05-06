/* Attack Theater — frontend. No framework. Connects to /stream WebSocket. */

(function () {
  'use strict';

  const WS_URL = `ws://${location.host}/stream`;
  const BACKOFF = [1000, 2000, 5000, 10000];

  // ── State ──────────────────────────────────────────────────────────────────
  let term = null;
  let fitAddon = null;
  let frameQueue = [];
  let sessionStart = null;
  let durationTimer = null;
  let backoffIdx = 0;
  let countries = {};
  let playbackSpeed = 1;

  // ── DOM refs ───────────────────────────────────────────────────────────────
  const elClock         = document.getElementById('clock');
  const elAttacksToday  = document.getElementById('attacks-today');
  const elSrcIp         = document.getElementById('src-ip');
  const elRdns          = document.getElementById('rdns');
  const elCountryFlag   = document.getElementById('country-flag');
  const elCountryName   = document.getElementById('country-name');
  const elAsnOrg        = document.getElementById('asn-org');
  const elHopTag        = document.getElementById('hop-tag');
  const elDuration      = document.getElementById('session-duration');
  const elBadge         = document.getElementById('session-badge');
  const elTicker        = document.getElementById('ticker-text');
  const elTopCountries  = document.getElementById('top-countries');
  const elMapPins       = document.getElementById('map-pins');
  const elDashboard     = document.getElementById('dashboard');
  const elTitleCard     = document.getElementById('title-card');
  const elMapContainer  = document.getElementById('map-container');
  const elSpeedSection  = document.getElementById('speed-section');
  const elSpeedBtns     = document.querySelectorAll('.speed-btn');

  // ── Playback speed ────────────────────────────────────────────────────────
  function setSpeed(n) {
    playbackSpeed = n;
    elSpeedBtns.forEach(btn => {
      btn.classList.toggle('active', Number(btn.dataset.speed) === n);
    });
  }

  elSpeedBtns.forEach(btn => {
    btn.addEventListener('click', () => setSpeed(Number(btn.dataset.speed)));
  });

  // ── Terminal setup ─────────────────────────────────────────────────────────
  function initTerminal() {
    if (term) { term.dispose(); }
    term = new Terminal({
      theme: { background: '#0d1117', foreground: '#c9d1d9', cursor: '#58a6ff' },
      fontFamily: "'Courier New', monospace",
      fontSize: 14,
      lineHeight: 1.3,
      cols: 220,
      rows: 50,
      scrollback: 500,
      convertEol: false,
    });
    const el = document.getElementById('terminal');
    el.innerHTML = '';
    term.open(el);
    term.focus();
  }

  // ── Clock ──────────────────────────────────────────────────────────────────
  function tickClock() {
    const now = new Date();
    elClock.textContent = now.toTimeString().slice(0, 8);
  }
  setInterval(tickClock, 1000);
  tickClock();

  // ── Session duration counter ───────────────────────────────────────────────
  function startDurationTimer() {
    sessionStart = Date.now();
    clearInterval(durationTimer);
    durationTimer = setInterval(() => {
      const secs = Math.floor((Date.now() - sessionStart) / 1000);
      const m = String(Math.floor(secs / 60)).padStart(2, '0');
      const s = String(secs % 60).padStart(2, '0');
      elDuration.textContent = `${m}:${s}`;
    }, 1000);
  }

  function stopDurationTimer() {
    clearInterval(durationTimer);
    durationTimer = null;
  }

  // ── Country flag from ISO code ─────────────────────────────────────────────
  function isoToFlag(code) {
    if (!code || code.length !== 2) return '';
    return String.fromCodePoint(
      code.toUpperCase().charCodeAt(0) - 65 + 0x1F1E6,
      code.toUpperCase().charCodeAt(1) - 65 + 0x1F1E6,
    );
  }

  // ── Map pin projection (equirectangular) ──────────────────────────────────
  function latLonToPercent(lat, lon) {
    const x = ((lon + 180) / 360) * 100;
    const y = ((90 - lat) / 180) * 100;
    return { x, y };
  }

  function addMapPin(lat, lon) {
    if (lat == null || lon == null) return;
    const pin = document.createElement('div');
    pin.className = 'map-pin';
    const { x, y } = latLonToPercent(lat, lon);
    pin.style.left = `${x}%`;
    pin.style.top  = `${y}%`;
    elMapPins.appendChild(pin);
    // Remove after animation completes (60s)
    setTimeout(() => pin.remove(), 60000);
  }

  // ── Ticker ─────────────────────────────────────────────────────────────────
  let tickerCommands = [];

  function pushCommand(cmd) {
    tickerCommands.unshift(cmd);
    if (tickerCommands.length > 20) tickerCommands.pop();
    elTicker.textContent = tickerCommands.join('  ·  ');
    // Restart scroll animation
    elTicker.style.animation = 'none';
    void elTicker.offsetWidth;
    elTicker.style.animation = '';
  }

  // ── Frame queue ────────────────────────────────────────────────────────────
  function flushFrames() { frameQueue = []; }

  // Normalise a raw Cowrie OUTPUT frame before handing it to xterm.js.
  //
  // Root cause of garbling: sessions that `cat` binary ELF files produce frames
  // containing C1 control bytes (e.g. 0x90 = DCS in 8-bit mode). xterm.js
  // interprets them as device-control sequences and enters DCS/OSC parser state,
  // silently consuming subsequent characters until a String Terminator arrives.
  //
  // Fixes applied:
  //  1. Strip standalone C1 bytes (0x80–0x9F) from the frame body. These are
  //     device-control escapes in 8-bit mode; only stripped when NOT a UTF-8
  //     continuation byte (i.e. preceding output byte is < 0xC0).
  //  2. Strip SO (0x0E) / SI (0x0F) from the body.
  //  3. Strip ESC[4h/ESC[4l (IRM insert mode). Cowrie emits these around every
  //     prompt; in xterm.js IRM causes each typed character to INSERT at the
  //     cursor, merging the prompt into preceding line content.
  //  4. Expand bare LF → CR LF. The Cowrie PTY records newlines as bare LF;
  //     we expand them ourselves so we don't rely on convertEol (which has
  //     known interaction bugs with IRM state in some xterm.js builds).
  //
  // NOTE: ESC \ (ST) and SI (0x0F) prefixes were tested and removed — both
  // shifted xterm.js cursor state in normal mode, causing off-by-one garbling.
  function normalizeFrame(u8) {
    // No prefix bytes — both ESC \ and SI (0x0F) were found to shift cursor
    // state in xterm.js normal mode and cause off-by-one garbling in command echo.
    // C1 stripping (below) is sufficient to prevent DCS entry from binary frames.
    const out = [];
    let i = 0;
    while (i < u8.length) {
      // Strip ESC [ 4 h  and  ESC [ 4 l  (IRM set / clear)
      if (i + 3 < u8.length &&
          u8[i] === 0x1B && u8[i+1] === 0x5B && u8[i+2] === 0x34 &&
          (u8[i+3] === 0x68 || u8[i+3] === 0x6C)) {
        i += 4;
        continue;
      }
      // Strip standalone C1 control bytes (0x80–0x9F) — device controls in 8-bit mode.
      // UTF-8 continuation bytes (also in 0x80–0xBF range) are preserved when the
      // preceding output byte is a UTF-8 start byte (≥ 0xC0).
      if (u8[i] >= 0x80 && u8[i] <= 0x9F) {
        const prev = out.length ? out[out.length - 1] : 0;
        if (prev < 0xC0) { i++; continue; }
      }
      // Strip SO (0x0E) and SI (0x0F) from body — charset reset by the prefix above
      if (u8[i] === 0x0E || u8[i] === 0x0F) {
        i++;
        continue;
      }
      // Expand bare LF → CR LF
      if (u8[i] === 0x0A) {
        out.push(0x0D);
      }
      out.push(u8[i++]);
    }
    return new Uint8Array(out);
  }

  function enqueueFrame(delay_ms, data) {
    const bytes = atob(data);
    const raw = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) raw[i] = bytes.charCodeAt(i);

    const u8 = normalizeFrame(raw);
    const effectiveDelay = Math.min(delay_ms, 2000) / playbackSpeed;
    frameQueue.push({ delay: effectiveDelay, data: u8 });
    if (frameQueue.length === 1) drainFrames();
  }

  function drainFrames() {
    if (!frameQueue.length) return;
    const { delay, data } = frameQueue.shift();
    setTimeout(() => {
      if (!term) { drainFrames(); return; }
      // Skip empty frames (stripped escape sequences) without calling term.write,
      // which avoids relying on xterm.js to invoke the callback for empty data.
      if (data.length === 0) { drainFrames(); return; }
      term.write(data, drainFrames);
    }, delay);
  }

  // ── UI helpers ─────────────────────────────────────────────────────────────
  function showDashboard() {
    elDashboard.classList.remove('hidden');
    elTitleCard.classList.add('hidden');
  }

  function showTitleCard() {
    elTitleCard.classList.remove('hidden');
    elDashboard.classList.add('hidden');
    stopDurationTimer();
    setBadge('idle');
    elDuration.textContent = '00:00';
    elSpeedSection.classList.add('hidden');
  }

  function setBadge(mode) {
    elBadge.className = 'badge';
    if (mode === 'live') {
      elBadge.classList.add('badge-live');
      elBadge.textContent = '⚡ LIVE';
    } else if (mode === 'replay') {
      elBadge.classList.add('badge-replay');
      elBadge.textContent = '▶ REPLAY';
    } else {
      elBadge.classList.add('badge-idle');
      elBadge.textContent = 'IDLE';
    }
  }

  function updateSidebar(session, mode) {
    const code = session.country_code || '';
    elSrcIp.textContent       = session.src_ip        || '—';
    elRdns.textContent        = '—';
    elCountryFlag.textContent = isoToFlag(code)        || '🌐';
    elCountryName.textContent = session.country        || 'Unknown';
    elAsnOrg.textContent      = session.asn_org        || '—';
    elHopTag.textContent      = `HOP ${session.hop || '?'}`;
    setBadge(mode);
    startDurationTimer();
  }

  function renderTopCountries(list) {
    elTopCountries.innerHTML = '';
    (list || []).forEach(entry => {
      const li   = document.createElement('li');
      const flag = document.createElement('span');
      const name = document.createElement('span');
      const cnt  = document.createElement('span');
      flag.className = 'tc-flag'; flag.textContent = isoToFlag(entry.country_code);
      name.className = 'tc-name'; name.textContent = entry.country;
      cnt.className  = 'tc-count'; cnt.textContent = entry.count.toLocaleString();
      li.append(flag, name, cnt);
      elTopCountries.appendChild(li);
    });
  }

  function renderPins(pins) {
    elMapPins.innerHTML = '';
    (pins || []).forEach(p => addMapPin(p.lat, p.lon));
  }

  // ── Message handlers ───────────────────────────────────────────────────────
  const handlers = {
    session_start(msg) {
      showDashboard();
      flushFrames();
      initTerminal();
      tickerCommands = [];
      elTicker.textContent = '';
      updateSidebar(msg.session || {}, msg.mode);
      if (msg.mode === 'live') {
        elSpeedSection.classList.add('hidden');
        term.writeln('\r\n\x1b[1;31m⚡ LIVE ATTACK — SWITCHING NOW\x1b[0m\r\n');
      } else {
        elSpeedSection.classList.remove('hidden');
      }
    },

    frame(msg) {
      enqueueFrame(msg.delay_ms, msg.data);
    },

    command(msg) {
      pushCommand(msg.command);
    },

    session_end() {
      stopDurationTimer();
      setBadge('idle');
    },

    stats(msg) {
      elAttacksToday.textContent = `${(msg.attacks_today || 0).toLocaleString()} attacks today`;
      renderTopCountries(msg.top_countries);
      renderPins(msg.recent_pins);
    },

    title_card() {
      showTitleCard();
    },
  };

  // ── WebSocket ──────────────────────────────────────────────────────────────
  function connect() {
    const ws = new WebSocket(WS_URL);

    ws.onopen = () => {
      backoffIdx = 0;
    };

    ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      const handler = handlers[msg.type];
      if (handler) handler(msg);
    };

    ws.onclose = () => {
      const delay = BACKOFF[Math.min(backoffIdx, BACKOFF.length - 1)];
      backoffIdx++;
      setTimeout(connect, delay);
    };

    ws.onerror = () => ws.close();
  }

  // ── Boot ──────────────────────────────────────────────────────────────────
  initTerminal();
  showTitleCard();
  connect();
})();
