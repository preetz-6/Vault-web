import { useState, useEffect, useRef } from 'react';
import Head from 'next/head';

// ── AES-256-GCM decrypt (mirrors CLI crypto.js) ────────────────────────────
async function decryptEntry(b64, password) {
  try {
    const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const salt = buf.slice(0, 32);
    const iv = buf.slice(32, 48);
    const tag = buf.slice(48, 64);
    const enc = buf.slice(64);
    const encWithTag = new Uint8Array(enc.length + tag.length);
    encWithTag.set(enc); encWithTag.set(tag, enc.length);

    const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
      km, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
    );
    const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, encWithTag);
    return JSON.parse(new TextDecoder().decode(dec));
  } catch { return null; }
}

// sha256('v::' + value) — matches CLI hashSecret
async function hashMasterAnswer(value) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('v::' + value.trim()));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

// sha256('sq::' + answer.toLowerCase()) — matches per-entry guard
async function hashEntryGuardAnswer(value) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('sq::' + value.trim().toLowerCase()));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

const CAT_LABELS = {
  'app-lock': 'App Lock',
  'login': 'Login',
  'bank': 'Bank',
  'wifi-other': 'Wi-Fi & Other',
  'app-password': 'App',
  'service': 'Service',
  'info': 'Info',
  'other': 'Other',
};

// SVG icons — no emojis
const IconLock = ({ size = 18, color = 'currentColor' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
  </svg>
);

const IconChevronRight = ({ size = 18, color = 'currentColor' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="9 18 15 12 9 6" />
  </svg>
);

const IconChevronLeft = ({ size = 20, color = 'currentColor' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="15 18 9 12 15 6" />
  </svg>
);

const IconCopy = ({ size = 15, color = 'currentColor' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
  </svg>
);

const IconEye = ({ size = 15, color = 'currentColor' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);

const IconEyeOff = ({ size = 15, color = 'currentColor' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
    <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);

const IconShield = ({ size = 14, color = 'currentColor' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);

const IconCheck = ({ size = 14, color = 'currentColor' }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="20 6 9 17 4 12" />
  </svg>
);

// ── Global CSS (dark theme only) ──────────────────────────────────────────────
const GLOBAL_CSS = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }

  :root {
    --bg:        #09090b;
    --bg-card:   #111113;
    --bg-input:  #0c0c0e;
    --border:    rgba(255,255,255,0.07);
    --border-focus: rgba(99,102,241,0.7);
    --accent:    #6366f1;
    --accent-dim:rgba(99,102,241,0.15);
    --accent-glow:rgba(99,102,241,0.25);
    --text:      #e4e4e7;
    --text2:     #71717a;
    --text3:     #3f3f46;
    --danger:    #f87171;
    --danger-dim:rgba(248,113,113,0.12);
    --success:   #34d399;
    --mono:      'JetBrains Mono', monospace;
    --sans:      'Inter', -apple-system, sans-serif;
    --r:         8px;
    --rs:        6px;
  }

  body {
    font-family: var(--sans);
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    -webkit-text-size-adjust: 100%;
    -webkit-font-smoothing: antialiased;
  }

  /* Subtle grid background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(99,102,241,0.025) 1px, transparent 1px),
      linear-gradient(90deg, rgba(99,102,241,0.025) 1px, transparent 1px);
    background-size: 48px 48px;
    pointer-events: none;
    z-index: 0;
  }

  * { position: relative; z-index: 1; }

  ::-webkit-scrollbar { width: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--text3); border-radius: 99px; }

  input, textarea {
    width: 100%;
    padding: 11px 14px;
    border: 1px solid var(--border);
    border-radius: var(--rs);
    font-size: 15px;
    font-family: var(--sans);
    color: var(--text);
    background: var(--bg-input);
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
    -webkit-appearance: none;
  }
  input:focus, textarea:focus {
    border-color: var(--border-focus);
    box-shadow: 0 0 0 3px var(--accent-glow);
  }
  input::placeholder { color: var(--text3); }

  button { cursor: pointer; font-family: var(--sans); border: none; }

  .btn-primary {
    padding: 11px 20px;
    background: var(--accent);
    color: #fff;
    border-radius: var(--rs);
    font-size: 14px;
    font-weight: 600;
    letter-spacing: 0.02em;
    transition: opacity 0.15s, transform 0.1s;
    box-shadow: 0 0 20px var(--accent-glow);
  }
  .btn-primary:hover { opacity: 0.88; }
  .btn-primary:active { transform: scale(0.98); }

  .btn-ghost {
    padding: 9px 14px;
    background: transparent;
    border: 1px solid var(--border);
    border-radius: var(--rs);
    font-size: 13px;
    font-weight: 500;
    color: var(--text2);
    display: inline-flex;
    align-items: center;
    gap: 6px;
    transition: border-color 0.15s, color 0.15s, background 0.15s;
  }
  .btn-ghost:hover { border-color: rgba(255,255,255,0.15); color: var(--text); background: rgba(255,255,255,0.04); }
  .btn-ghost:active { transform: scale(0.98); }

  .btn-ghost.copied {
    border-color: var(--success);
    color: var(--success);
  }

  .error-text {
    font-size: 13px;
    color: var(--danger);
    margin-top: 8px;
    padding: 8px 12px;
    background: var(--danger-dim);
    border-radius: var(--rs);
    border: 1px solid rgba(248,113,113,0.2);
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(6px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes spin {
    to { transform: rotate(360deg); }
  }
  .fade-in { animation: fadeIn 0.2s ease-out both; }

  .card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: var(--r);
  }

  .label-micro {
    font-size: 10px;
    font-weight: 600;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--text2);
  }

  .mono { font-family: var(--mono); }
`;

export default function Home() {
  const [stage, setStage] = useState('pw');
  const [password, setPassword] = useState('');
  const [sqQuestion, setSqQuestion] = useState('');
  const [sqAnswer, setSqAnswer] = useState('');
  const [sqHash, setSqHash] = useState('');
  const [error, setError] = useState('');
  const [rawEntries, setRaw] = useState([]);
  const [entries, setEntries] = useState([]);
  const [search, setSearch] = useState('');
  const [cat, setCat] = useState('all');
  const [selected, setSelected] = useState(null);
  const [showPw, setShowPw] = useState(false);
  const [copying, setCopying] = useState('');

  // Per-entry secret guard
  const [guardState, setGuardState] = useState('locked');
  const [guardAnswer, setGuardAnswer] = useState('');
  const [guardError, setGuardError] = useState('');

  const sqRef = useRef(null);

  // ── Back button (mobile) ─────────────────────────────────────────────────────
  useEffect(() => {
    const handlePop = () => {
      setError('');
      if (selected) {
        setSelected(null); setShowPw(false); resetGuard();
        history.pushState({ page: 'list' }, '');
      } else if (stage === 'app') {
        setStage('pw'); setPassword(''); setEntries([]); setRaw([]);
      }
    };
    window.addEventListener('popstate', handlePop);
    return () => window.removeEventListener('popstate', handlePop);
  }, [stage, selected]);

  useEffect(() => { if (stage === 'app' && !selected) history.pushState({ page: 'list' }, ''); }, [stage]);
  useEffect(() => { if (selected) history.pushState({ page: 'detail' }, ''); }, [selected]);

  function resetGuard() { setGuardState('locked'); setGuardAnswer(''); setGuardError(''); }

  // ── Step 1: master password ──────────────────────────────────────────────────
  async function handlePasswordSubmit() {
    if (!password) return;
    setError(''); setStage('loading');
    try {
      const res = await fetch('/api/entries');
      const json = await res.json();
      if (json.error) throw new Error(json.error);
      const raw = json.entries || [];

      if (raw.length === 0) {
        setError('Vault is empty. Add entries from the desktop app first.');
        setStage('pw'); return;
      }

      const test = await decryptEntry(raw[0].encrypted, password);
      if (!test) { setError('Incorrect password.'); setStage('pw'); return; }

      const cfgRes = await fetch('/api/config');
      const cfgJson = await cfgRes.json();
      const cfg = cfgJson.config || {};
      setRaw(raw);

      if (cfg.security_question && cfg.security_question_hash) {
        setSqQuestion(cfg.security_question);
        setSqHash(cfg.security_question_hash);
        setStage('sq');
        setTimeout(() => sqRef.current?.focus(), 100);
      } else {
        await unlockWithEntries(raw);
      }
    } catch {
      setError('Connection error. Please try again.');
      setStage('pw');
    }
  }

  // ── Step 2: security question ────────────────────────────────────────────────
  async function handleSqSubmit() {
    if (!sqAnswer) return;
    setError('');
    const hash = await hashMasterAnswer(sqAnswer);
    if (hash !== sqHash) {
      setError('Incorrect answer.');
      setSqAnswer('');
      setTimeout(() => sqRef.current?.focus(), 50);
      return;
    }
    setStage('loading');
    await unlockWithEntries(rawEntries);
  }

  async function unlockWithEntries(raw) {
    const decrypted = await Promise.all(raw.map(async e => {
      const d = await decryptEntry(e.encrypted, password);
      return d ? { ...e, data: d } : null;
    }));
    setEntries(decrypted.filter(Boolean));
    setStage('app');
  }

  // ── Per-entry guard verify ───────────────────────────────────────────────────
  async function verifyGuardAnswer() {
    if (!guardAnswer) return;
    const hash = await hashEntryGuardAnswer(guardAnswer);
    if (hash === selected.data.secretAnswerHash) {
      setGuardState('unlocked'); setGuardError('');
    } else {
      setGuardError('Incorrect answer.'); setGuardAnswer('');
    }
  }

  // ── Filtering ────────────────────────────────────────────────────────────────
  const filtered = entries.filter(e => {
    const matchCat = cat === 'all' || e.category === cat;
    const q = search.toLowerCase();
    const matchQ = !q || [e.data.name, e.data.username, e.data.url, e.data.notes, e.category]
      .some(v => (v || '').toLowerCase().includes(q));
    return matchCat && matchQ;
  });

  const allCats = [...new Set(entries.map(e => e.category))];
  const counts = { all: entries.length };
  allCats.forEach(c => { counts[c] = entries.filter(e => e.category === c).length; });

  async function copyText(text, key) {
    try { await navigator.clipboard.writeText(text); } catch { return; }
    setCopying(key);
    setTimeout(() => setCopying(''), 2000);
  }

  const headMeta = (title = 'Vault') => (
    <Head>
      <title>{title}</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
      <meta name="theme-color" content="#09090b" />
      <meta name="apple-mobile-web-app-capable" content="yes" />
      <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
    </Head>
  );

  // ─────────────────────────────────────────────────────────────────────────────
  // AUTH SCREENS (pw | sq | loading)
  // ─────────────────────────────────────────────────────────────────────────────
  if (stage === 'pw' || stage === 'sq' || stage === 'loading') {
    const isLoading = stage === 'loading';
    const isSq = stage === 'sq';

    return (
      <>
        {headMeta()}
        <style>{GLOBAL_CSS}</style>
        <div style={{
          minHeight: '100vh', display: 'flex', alignItems: 'center',
          justifyContent: 'center', padding: '1.5rem',
        }}>
          <div className="card fade-in" style={{
            width: '100%', maxWidth: 380,
            padding: '2.5rem 2rem',
            boxShadow: '0 0 60px rgba(99,102,241,0.08)',
          }}>
            {/* Brand */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: '2rem' }}>
              <div style={{
                width: 34, height: 34, borderRadius: var_r,
                background: 'var(--accent-dim)', border: '1px solid rgba(99,102,241,0.3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <IconLock size={16} color="var(--accent)" />
              </div>
              <span style={{ fontSize: 17, fontWeight: 700, letterSpacing: '-0.02em', color: 'var(--text)' }}>
                Vault
              </span>
            </div>

            {/* Step label */}
            <div style={{ marginBottom: '1.5rem' }}>
              <div className="label-micro" style={{ marginBottom: 6 }}>
                {isSq ? 'Step 2 of 2' : 'Step 1 of 2'}
              </div>
              <h1 style={{ fontSize: 20, fontWeight: 600, color: 'var(--text)', lineHeight: 1.3 }}>
                {isSq ? 'Security question' : 'Master password'}
              </h1>
              {isSq && (
                <p style={{ fontSize: 13, color: 'var(--text2)', marginTop: 6, lineHeight: 1.5 }}>
                  {sqQuestion}
                </p>
              )}
            </div>

            {isLoading ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '1rem 0', color: 'var(--text2)', fontSize: 14 }}>
                <div style={{
                  width: 16, height: 16, border: '2px solid var(--text3)',
                  borderTopColor: 'var(--accent)', borderRadius: '50%',
                  animation: 'spin 0.7s linear infinite', flexShrink: 0,
                }} />
                Decrypting vault…
              </div>
            ) : (
              <>
                <div style={{ marginBottom: '1rem' }}>
                  <input
                    ref={isSq ? sqRef : undefined}
                    type="password"
                    placeholder={isSq ? 'Your answer' : 'Enter master password'}
                    value={isSq ? sqAnswer : password}
                    onChange={e => isSq ? setSqAnswer(e.target.value) : setPassword(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && (isSq ? handleSqSubmit() : handlePasswordSubmit())}
                    autoFocus={!isSq}
                  />
                  {error && <div className="error-text">{error}</div>}
                </div>

                <div style={{ display: 'flex', gap: 8 }}>
                  {isSq && (
                    <button className="btn-ghost" style={{ flex: 1 }}
                      onClick={() => { setStage('pw'); setSqAnswer(''); setError(''); }}>
                      Back
                    </button>
                  )}
                  <button
                    className="btn-primary"
                    style={{ flex: isSq ? 2 : 1, width: isSq ? 'auto' : '100%' }}
                    onClick={isSq ? handleSqSubmit : handlePasswordSubmit}
                  >
                    {isSq ? 'Unlock' : 'Continue'}
                  </button>
                </div>
              </>
            )}

            {/* Security footnote */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6,
              marginTop: '1.75rem', paddingTop: '1.25rem',
              borderTop: '1px solid var(--border)',
              color: 'var(--text3)', fontSize: 11,
            }}>
              <IconShield size={12} color="var(--text3)" />
            </div>
          </div>
        </div>
      </>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // LIST VIEW
  // ─────────────────────────────────────────────────────────────────────────────
  if (stage === 'app' && !selected) {
    return (
      <>
        {headMeta()}
        <style>{GLOBAL_CSS}</style>

        {/* Header */}
        <div style={{
          background: 'rgba(9,9,11,0.85)',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          borderBottom: '1px solid var(--border)',
          padding: '0 1rem', height: 52,
          display: 'flex', alignItems: 'center', gap: 10,
          position: 'sticky', top: 0, zIndex: 50,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
            <IconLock size={15} color="var(--accent)" />
            <span style={{ fontWeight: 700, fontSize: 15, letterSpacing: '-0.01em' }}>Vault</span>
          </div>
          <span style={{ fontSize: 12, color: 'var(--text3)', fontVariantNumeric: 'tabular-nums' }}>
            {entries.length} {entries.length === 1 ? 'entry' : 'entries'}
          </span>
        </div>

        {/* Search */}
        <div style={{ padding: '0.875rem 1rem 0' }}>
          <input
            type="search"
            placeholder="Search"
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </div>

        {/* Category pills */}
        {allCats.length > 1 && (
          <div style={{
            display: 'flex', gap: 6, padding: '0.625rem 1rem',
            overflowX: 'auto', scrollbarWidth: 'none',
          }}>
            {[['all', 'All'], ...allCats.map(c => [c, CAT_LABELS[c] || c])].map(([k, label]) => (
              <button key={k} onClick={() => setCat(k)} style={{
                padding: '5px 12px', borderRadius: 99,
                fontSize: 12, fontWeight: cat === k ? 600 : 400,
                whiteSpace: 'nowrap', flexShrink: 0,
                background: cat === k ? 'var(--accent)' : 'transparent',
                color: cat === k ? '#fff' : 'var(--text2)',
                border: `1px solid ${cat === k ? 'var(--accent)' : 'var(--border)'}`,
                transition: 'all 0.15s',
              }}>
                {label}
                <span style={{ opacity: 0.6, marginLeft: 4 }}>({counts[k] ?? 0})</span>
              </button>
            ))}
          </div>
        )}

        {/* Entries */}
        <div style={{ padding: '0.5rem 1rem 4rem', display: 'flex', flexDirection: 'column', gap: 6 }}>
          {filtered.length === 0 && (
            <div className="fade-in" style={{
              textAlign: 'center', padding: '4rem 0',
              color: 'var(--text3)', fontSize: 14,
            }}>
              No entries found
            </div>
          )}
          {filtered.map((e, i) => (
            <div
              key={e.id}
              className="card fade-in"
              onClick={() => { setSelected(e); resetGuard(); }}
              style={{
                padding: '13px 14px',
                display: 'flex', alignItems: 'center', gap: 12,
                cursor: 'pointer', userSelect: 'none',
                transition: 'border-color 0.15s, background 0.15s',
                animationDelay: `${i * 0.03}s`,
              }}
              onMouseEnter={el => { if (el.currentTarget) el.currentTarget.style.borderColor = 'rgba(255,255,255,0.12)'; }}
              onMouseLeave={el => { if (el.currentTarget) el.currentTarget.style.borderColor = 'var(--border)'; }}
            >
              {/* Category pill */}
              <div style={{
                flexShrink: 0,
                fontSize: 10, fontWeight: 600, letterSpacing: '0.06em',
                textTransform: 'uppercase',
                color: 'var(--accent)',
                background: 'var(--accent-dim)',
                border: '1px solid rgba(99,102,241,0.2)',
                borderRadius: 4,
                padding: '3px 7px',
              }}>
                {CAT_LABELS[e.category] || e.category}
              </div>

              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontWeight: 600, fontSize: 14,
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                  color: 'var(--text)',
                }}>
                  {e.data.name}
                </div>
                {(e.data.username || e.data.url) && (
                  <div style={{
                    fontSize: 12, color: 'var(--text2)', marginTop: 2,
                    whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                  }}>
                    {e.data.username || e.data.url}
                  </div>
                )}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
                {e.data.hasSecretGuard && (
                  <span style={{ color: 'var(--text3)' }}>
                    <IconShield size={13} color="var(--text3)" />
                  </span>
                )}
                <IconChevronRight size={16} color="var(--text3)" />
              </div>
            </div>
          ))}
        </div>
      </>
    );
  }

  // ─────────────────────────────────────────────────────────────────────────────
  // DETAIL VIEW
  // ─────────────────────────────────────────────────────────────────────────────
  if (stage === 'app' && selected) {
    const d = selected.data;
    const isGuarded = !!d.hasSecretGuard && !!d.secretAnswerHash;
    const secretLabel = selected.category === 'bank' ? 'PIN / UPI PIN' : 'Password';
    const secretValue = selected.category === 'bank' ? d.pin : d.password;

    const plainFields = [
      ['Account name', d.name],
      ['URL', d.url],
      ['Username / email', d.username],
      ['Device', d.device],
      ['Notes', d.notes],
      ['Extra', d.extra],
    ].filter(([, v]) => v);

    const FieldCard = ({ label, value, fieldKey, mono = false }) => (
      <div className="card" style={{ padding: '12px 14px' }}>
        <div className="label-micro" style={{ marginBottom: 6 }}>{label}</div>
        <div style={{
          fontSize: 14, color: 'var(--text)', lineHeight: 1.5,
          wordBreak: 'break-all',
          fontFamily: mono ? 'var(--mono)' : 'var(--sans)',
        }}>
          {value}
        </div>
        <button
          className={`btn-ghost${copying === fieldKey ? ' copied' : ''}`}
          style={{ marginTop: 10, fontSize: 12 }}
          onClick={() => copyText(value, fieldKey)}
        >
          {copying === fieldKey
            ? <><IconCheck size={13} color="var(--success)" /> Copied</>
            : <><IconCopy size={13} /> Copy</>}
        </button>
      </div>
    );

    return (
      <>
        {headMeta(`${d.name} — Vault`)}
        <style>{GLOBAL_CSS}</style>

        {/* Header */}
        <div style={{
          background: 'rgba(9,9,11,0.85)',
          backdropFilter: 'blur(12px)',
          WebkitBackdropFilter: 'blur(12px)',
          borderBottom: '1px solid var(--border)',
          padding: '0 0.75rem', height: 52,
          display: 'flex', alignItems: 'center', gap: 6,
          position: 'sticky', top: 0, zIndex: 50,
        }}>
          <button
            onClick={() => { setSelected(null); setShowPw(false); resetGuard(); history.back(); }}
            style={{
              background: 'none', padding: '6px 8px',
              display: 'flex', alignItems: 'center',
              color: 'var(--accent)', borderRadius: var_rs,
              transition: 'background 0.1s',
            }}
            onMouseEnter={el => { el.currentTarget.style.background = 'var(--accent-dim)'; }}
            onMouseLeave={el => { el.currentTarget.style.background = 'none'; }}
          >
            <IconChevronLeft size={22} color="var(--accent)" />
          </button>
          <span style={{
            fontWeight: 600, fontSize: 15, flex: 1,
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            letterSpacing: '-0.01em',
          }}>
            {d.name}
          </span>
          <div style={{
            fontSize: 10, fontWeight: 600, letterSpacing: '0.06em',
            textTransform: 'uppercase', color: 'var(--accent)',
            background: 'var(--accent-dim)', border: '1px solid rgba(99,102,241,0.2)',
            borderRadius: 4, padding: '3px 7px', flexShrink: 0,
          }}>
            {CAT_LABELS[selected.category] || selected.category}
          </div>
        </div>

        <div className="fade-in" style={{
          padding: '1rem 1rem 4rem',
          display: 'flex', flexDirection: 'column', gap: 8,
        }}>
          {/* Plain text fields */}
          {plainFields.map(([label, val]) => (
            <FieldCard key={label} label={label} value={val} fieldKey={label} />
          ))}

          {/* Secret field */}
          {secretValue && (
            <div className="card" style={{ padding: '12px 14px' }}>
              <div className="label-micro" style={{ marginBottom: 6 }}>{secretLabel}</div>

              {/* Locked guard state */}
              {isGuarded && guardState === 'locked' && (
                <div>
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 7,
                    fontSize: 13, color: 'var(--text2)', marginBottom: 12,
                  }}>
                    <IconShield size={13} color="var(--text2)" />
                    Protected by a secret question
                  </div>
                  <button className="btn-ghost" onClick={() => setGuardState('prompting')}>
                    Reveal
                  </button>
                </div>
              )}

              {/* Prompting for guard answer */}
              {isGuarded && guardState === 'prompting' && (
                <div>
                  <p style={{ fontSize: 13, color: 'var(--text2)', marginBottom: 10, lineHeight: 1.5 }}>
                    {d.secretQuestion}
                  </p>
                  <input
                    type="password"
                    placeholder="Your answer"
                    value={guardAnswer}
                    onChange={e => setGuardAnswer(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && verifyGuardAnswer()}
                    autoFocus
                    style={{ marginBottom: guardError ? 0 : 10 }}
                  />
                  {guardError && <div className="error-text" style={{ marginBottom: 10 }}>{guardError}</div>}
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-ghost"
                      onClick={() => { setGuardState('locked'); setGuardAnswer(''); setGuardError(''); }}>
                      Cancel
                    </button>
                    <button className="btn-primary" style={{ padding: '9px 18px', fontSize: 13 }}
                      onClick={verifyGuardAnswer}>
                      Confirm
                    </button>
                  </div>
                </div>
              )}

              {/* Revealed / unguarded */}
              {(!isGuarded || guardState === 'unlocked') && (
                <div>
                  <div className="mono" style={{
                    fontSize: 15, color: 'var(--text)',
                    letterSpacing: showPw ? '0.05em' : '0.18em',
                    wordBreak: 'break-all', marginBottom: 12,
                    padding: '10px 12px',
                    background: 'var(--bg)',
                    borderRadius: var_rs,
                    border: '1px solid var(--border)',
                    minHeight: 42,
                    display: 'flex', alignItems: 'center',
                  }}>
                    {showPw ? secretValue : '•'.repeat(Math.min(secretValue.length, 20))}
                  </div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-ghost"
                      style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                      onClick={() => setShowPw(p => !p)}>
                      {showPw ? <IconEyeOff size={14} /> : <IconEye size={14} />}
                      {showPw ? 'Hide' : 'Show'}
                    </button>
                    <button
                      className={`btn-ghost${copying === 'secret' ? ' copied' : ''}`}
                      onClick={() => copyText(secretValue, 'secret')}>
                      {copying === 'secret'
                        ? <><IconCheck size={13} color="var(--success)" /> Copied</>
                        : <><IconCopy size={13} /> Copy</>}
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </>
    );
  }

  return null;
}

// CSS variable shorthands for inline styles (Next.js doesn't support CSS vars in style prop directly without quotes)
const var_r = 'var(--r)';
const var_rs = 'var(--rs)';
