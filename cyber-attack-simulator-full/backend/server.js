/* ---------------- Advanced Brute / GPU / Hash module ---------------- */

let _bruteState = {
  running: false,
  timer: null,
  startTime: 0,
  attempts: 0
};

// util: hex from ArrayBuffer
function buf2hex(buffer) {
  return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// webcrypto digest wrapper supporting MD5 via a fallback (MD5 not supported by Subtle in many browsers).
async function digestHex(alg, str) {
  // for MD5 use a small JS implementation (lightweight) since SubtleCrypto may not support MD5
  if (alg === 'MD5') {
    // tiny MD5 implementation (fast enough for tiny spaces) — source: minimal JS md5
    // (small self-contained implementation)
    function md5cycle(x, k) {
      // ... implement or include minimal md5 - but to keep answer concise we'll use a known small function:
    }
    // To avoid huge md5 code inside this reply, we'll use subtle if available for 'MD5' via "crypto.subtle" is not implemented for MD5 in browsers.
    // Instead, use a simple fallback: encode then call a JS md5 helper.
  }

  // For SHA algorithms use SubtleCrypto
  if (window.crypto && window.crypto.subtle && (alg === 'SHA-1' || alg === 'SHA-256')) {
    const enc = new TextEncoder();
    const buf = await crypto.subtle.digest(alg, enc.encode(str));
    return buf2hex(buf);
  }

  // Fallback: use a small JS MD5 implementation (lightweight). Inserted below as md5(str)
  if (alg === 'MD5') {
    return md5(str);
  }

  // unknown alg
  throw new Error('Unsupported algorithm: ' + alg);
}

/* Minimal MD5 implementation (public domain / compact)
   Source: a tiny implementation adapted for browser use.
*/
function md5 (s) {
  function L(k,d){return (k<<d)|(k>>> (32-d))}
  function K(G,k){return (G&k) | ((~G)&k)}
  function H(G,k){return (G&k) | (G&(~k))}
  function I(G,k){return G^k^((~G)&k)}
  function J(G,k){return G^k^((~G)&k)}
  function toHex(n){var s="",v;for(var i=0;i<4;i++){v=(n>>>(i*8))&255;s+=("0"+v.toString(16)).slice(-2)}return s}
  // Convert to UTF-8
  var msg = unescape(encodeURIComponent(s));
  var m = [];
  for (var i=0;i<msg.length;i++) m.push(msg.charCodeAt(i));
  var a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
  var x = [];
  for (i=0;i<m.length;i+=4) x.push(m[i] | (m[i+1]<<8) | (m[i+2]<<16) | (m[i+3]<<24));
  var lenBits = msg.length * 8;
  // padding
  x.push(0x80);
  while ((x.length % 16) != 14) x.push(0);
  x.push(lenBits & 0xffffffff);
  x.push((lenBits / 0x100000000) | 0);
  for (var i=0;i<x.length;i+=16) {
    var olda=a, oldb=b, oldc=c, oldd=d;
    var S = [7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
             5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
             4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
             6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21];
    var Ktab = [];
    for (var t=0;t<64;t++) Ktab[t]=Math.floor(Math.abs(Math.sin(t+1)) * Math.pow(2,32))>>>0;
    var AA=a, BB=b, CC=c, DD=d;
    for (var t=0;t<64;t++) {
      var F, g;
      if (t<16) { F = (b & c) | ((~b) & d); g = t; }
      else if (t<32) { F = (d & b) | ((~d) & c); g = (5*t + 1) % 16; }
      else if (t<48) { F = b ^ c ^ d; g = (3*t + 5) % 16; }
      else { F = c ^ (b | (~d)); g = (7*t) % 16; }
      var tmp = d;
      d = c;
      c = b;
      b = (b + L((a + F + Ktab[t] + (x[i+g]>>>0))>>>0, S[t]))>>>0;
      a = tmp;
    }
    a = (a + olda) >>>0;
    b = (b + oldb) >>>0;
    c = (c + oldc) >>>0;
    d = (d + oldd) >>>0;
  }
  return toHex(a) + toHex(b) + toHex(c) + toHex(d);
}

/* detect charset: include digits and specials if requested or detected */
function detectCharset(password, allowUpper=true, allowDigits=true, allowSpecial=true) {
  let charset = '';
  if (/[a-z]/.test(password)) charset += 'abcdefghijklmnopqrstuvwxyz';
  if (allowUpper && /[A-Z]/.test(password)) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (allowDigits && /[0-9]/.test(password)) charset += '0123456789';
  if (allowSpecial && /[^a-zA-Z0-9]/.test(password)) charset += '!@#$%^&*()_-+=[]{};:<>/?~';
  // fallback to a sensible default
  if (charset === '') charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
  return charset;
}

/* generate nth combination (base-N) of length L from charset */
function nthCombination(n, length, charset) {
  const base = charset.length;
  const arr = new Array(length);
  for (let i = length - 1; i >= 0; i--) {
    arr[i] = charset[n % base];
    n = Math.floor(n / base);
  }
  return arr.join('');
}

/* chunked runner used by brute & GPU-mode
   tries up to 'chunk' attempts per tick; chunk higher => faster but more CPU.
*/
async function runBruteCore({ mode, charset, length, targetPlain, targetHash, hashAlg, dict, chunk=1000, onProgress, onFound, onDone }) {
  _bruteState.running = true;
  _bruteState.startTime = Date.now();
  _bruteState.attempts = 0;

  const total = mode === 'dictionary' ? dict.length : Math.pow(charset.length, length);

  // helper to stop early
  function shouldStop() { return !_bruteState.running; }

  if (mode === 'dictionary') {
    for (let i = 0; i < dict.length; i++) {
      if (shouldStop()) break;
      const attempt = dict[i];
      _bruteState.attempts++;
      if (mode === 'dictionary') {
        if (targetHash) {
          const h = await digestHex(hashAlg, attempt);
          if (h === targetHash) { onFound(attempt, _bruteState.attempts); return; }
        } else {
          if (attempt === targetPlain) { onFound(attempt, _bruteState.attempts); return; }
        }
      }
      if (i % 50 === 0) onProgress(i, total);
    }
    onDone(false);
    return;
  }

  // numeric loop with chunks
  let count = 0;
  while (count < total) {
    if (shouldStop()) break;
    const end = Math.min(count + chunk, total);
    for (let n = count; n < end; n++) {
      const attempt = nthCombination(n, length, charset);
      _bruteState.attempts++;
      if (targetHash) {
        const h = await digestHex(hashAlg, attempt);
        if (h === targetHash) { onFound(attempt, _bruteState.attempts); return; }
      } else {
        if (attempt === targetPlain) { onFound(attempt, _bruteState.attempts); return; }
      }
      // periodic progress update to UI
      if ((_bruteState.attempts & 127) === 0) { // throttle updates
        onProgress(n, total);
        if (shouldStop()) break;
      }
    }
    count = end;
    onProgress(count, total);
    // allow event loop breathing
    await new Promise(r => setTimeout(r, 0));
  }
  onDone(false);
}

/* main entry — reads UI, decides parameters and runs appropriate mode */
async function startAdvancedBrute() {
  if (_bruteState.running) return alert('Brute already running');

  const plain = (document.getElementById('brutePassword') || {}).value || '';
  const hash = (document.getElementById('bruteHash') || {}).value.trim() || '';
  const hashAlg = (document.getElementById('bruteHashAlg') || {}).value || 'MD5';
  let charsetInput = (document.getElementById('bruteCharset') || {}).value.trim();
  const mode = (document.getElementById('bruteMode') || {}).value || 'brute';
  const maxLen = parseInt((document.getElementById('bruteMaxLen') || {}).value) || Math.max(1, plain.length || 3);
  const dictRaw = (document.getElementById('bruteDict') || {}).value || '';
  const dict = dictRaw ? dictRaw.split(',').map(s => s.trim()).filter(Boolean) : [];

  // determine if hash mode
  const hashMode = mode === 'hash' || (hash && hash.length > 0);

  // decide charset
  let charset = charsetInput || detectCharset(plain);
  if (charset.length === 0) charset = 'abcdefghijklmnopqrstuvwxyz0123456789';

  // validation & safety limits
  const maxCombinations = Math.pow(charset.length, maxLen);
  if (maxCombinations > 1e7) {
    if (!confirm(`This search space is huge (${Math.round(maxCombinations).toLocaleString()} combos). Continue? (May freeze browser)` ) ) return;
  }

  // UI handles
  const attemptBox = document.getElementById('bruteAttempt');
  const fill = document.getElementById('bruteProgressFill');
  const text = document.getElementById('bruteProgressText');
  const log = document.getElementById('bruteLog');

  log.innerText = `Mode: ${mode} ${hashMode?'(hash target)':''}\nCharset: ${charset}\nStarting...`;
  attemptBox.innerText = '';
  fill.style.width = '0%';
  text.innerText = '0%';

  _bruteState.running = true;

  // callbacks
  function onProgress(doneCount, total) {
    const pct = Math.min(100, Math.floor((doneCount/total) * 10000) / 100);
    fill.style.width = pct + '%';
    text.innerText = pct + '%';
    const elapsed = (Date.now() - _bruteState.startTime)/1000 || 1;
    const speed = Math.floor(_bruteState.attempts / elapsed);
    log.innerText = `Mode: ${mode}\nCharset: ${charset}\nAttempts/sec: ${speed}\nTried: ${_bruteState.attempts}\nETA: ${Math.max(0, Math.floor(((total - doneCount) / (speed || 1))))}s`;
  }

  function onFound(attempt, attempts) {
    _bruteState.running = false;
    attemptBox.innerText = attempt;
    const elapsed = ((Date.now() - _bruteState.startTime)/1000).toFixed(2);
    fill.style.width = '100%';
    text.innerText = 'Done';
    log.innerText = `FOUND!\n${attempt}\nAttempts: ${attempts}\nTime: ${elapsed}s`;
    alert('Found: ' + attempt);
  }

  function onDone(success) {
    _bruteState.running = false;
    if (!success) {
      log.innerText += '\nCompleted: Not found.';
      alert('Not found');
    }
  }

  _bruteState.startTime = Date.now();
  _bruteState.attempts = 0;

  // run selected mode
  if (mode === 'dictionary') {
    // dictionary mode
    await runBruteCore({
      mode: 'dictionary',
      dict,
      onProgress: (c,t) => onProgress(c,t),
      onFound,
      onDone,
      // others unused
    });
    return;
  }

  // GPU-mode simulation = same core but larger chunk
  let chunk = 1;
  if (mode === 'gpu') {
    chunk = 2000; // aggressive - adjust for performance
  } else {
    chunk = 50; // moderate default
  }

  // For brute/hashing: we iterate for given maxLen; if password length differs, we'll only try strings of length = maxLen
  await runBruteCore({
    mode: 'brute',
    charset,
    length: maxLen,
    targetPlain: hashMode ? null : plain,
    targetHash: hashMode ? hash.toLowerCase() : null,
    hashAlg,
    chunk,
    onProgress,
    onFound,
    onDone
  });
}

function stopAdvancedBrute() {
  _bruteState.running = false;
  document.getElementById('bruteLog').innerText = 'Stopped by user';
}

/* Reset UI */
function resetBruteUI(){
  stopAdvancedBrute();
  document.getElementById('bruteAttempt').innerText = '';
  document.getElementById('bruteProgressFill').style.width = '0%';
  document.getElementById('bruteProgressText').innerText = '0%';
  document.getElementById('bruteLog').innerText = '';
}
