import { useState, useEffect } from 'react';
import Head from 'next/head';

// ── AES-256-GCM decrypt (mirrors CLI crypto.js) ────────────────────────────
async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const km  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
    km,
    { name: 'AES-CBC', length: 256 },
    false,
    ['decrypt']
  );
}

// NOTE: CLI uses Node crypto (AES-256-GCM). We replicate it here via WebCrypto.
async function decryptEntry(b64, password) {
  try {
    const buf  = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const salt = buf.slice(0, 32);
    const iv   = buf.slice(32, 48);
    const tag  = buf.slice(48, 64);
    const enc  = buf.slice(64);

    // WebCrypto doesn't have AES-GCM with separated tag import directly,
    // so we concatenate enc+tag as GCM expects
    const encWithTag = new Uint8Array(enc.length + tag.length);
    encWithTag.set(enc); encWithTag.set(tag, enc.length);

    const km  = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
      km,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
    const dec = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, encWithTag);
    return JSON.parse(new TextDecoder().decode(dec));
  } catch {
    return null;
  }
}

const CAT_ICONS = {
  'app-password': '📱',
  'app-lock':     '🔑',
  'service':      '🌐',
  'info':         '📝',
  'other':        '📦'
};

const CAT_COLORS = {
  'app-password': '#e6f1fb',
  'app-lock':     '#eaf3de',
  'service':      '#faeeda',
  'info':         '#eeedfe',
  'other':        '#f5f5f4'
};

export default function Home() {
  const [stage, setStage]     = useState('unlock'); // unlock | loading | app
  const [password, setPassword] = useState('');
  const [error, setError]     = useState('');
  const [rawEntries, setRaw]  = useState([]);
  const [entries, setEntries] = useState([]);
  const [search, setSearch]   = useState('');
  const [cat, setCat]         = useState('all');
  const [selected, setSelected] = useState(null);
  const [showPw, setShowPw]   = useState(false);
  const [copying, setCopying] = useState('');

  async function unlock() {
    if (!password) return;
    setError(''); setStage('loading');
    try {
      const res  = await fetch('/api/entries');
      const json = await res.json();
      const raw  = json.entries || [];
      setRaw(raw);

      // Try decrypting the first entry to validate password
      if (raw.length > 0) {
        const test = await decryptEntry(raw[0].encrypted, password);
        if (!test) { setError('Wrong password.'); setStage('unlock'); return; }
      }

      // Decrypt all
      const decrypted = await Promise.all(raw.map(async e => {
        const d = await decryptEntry(e.encrypted, password);
        return d ? { ...e, data: d } : null;
      }));
      setEntries(decrypted.filter(Boolean));
      setStage('app');
    } catch(e) {
      setError('Failed to load vault. Check connection.'); setStage('unlock');
    }
  }

  const filtered = entries.filter(e => {
    const matchCat = cat === 'all' || e.category === cat;
    const q = search.toLowerCase();
    const matchQ = !q || [e.data.name, e.data.username, e.data.url, e.data.notes, e.category]
      .some(v => (v||'').toLowerCase().includes(q));
    return matchCat && matchQ;
  });

  const counts = { all: entries.length };
  ['app-password','app-lock','service','info','other'].forEach(c => {
    counts[c] = entries.filter(e => e.category === c).length;
  });

  async function copyText(text, key) {
    await navigator.clipboard.writeText(text);
    setCopying(key); setTimeout(() => setCopying(''), 1500);
  }

  return (
    <>
      <Head>
        <title>My Vault</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="theme-color" content="#185FA5" />
      </Head>

      <style>{`
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f4; color: #1a1a18; min-height: 100vh; }
        :root { --accent: #185FA5; --accent-h: #0c4478; --accent-l: #e6f1fb; --surface: #fff; --border: #e5e5e3; --border2: #d4d4d1; --text2: #6b6b68; --text3: #9c9c99; --r: 10px; --rs: 7px; }
        @media (prefers-color-scheme: dark) {
          body { background: #111110; color: #f0f0ee; }
          :root { --accent: #4a9ede; --accent-h: #378ADD; --accent-l: #0d2236; --surface: #1c1c1a; --border: #2e2e2b; --border2: #3d3d3a; --text2: #a0a09c; --text3: #666663; }
        }
        input { width: 100%; padding: 11px 14px; border: 1px solid var(--border2); border-radius: var(--rs); font-size: 15px; color: inherit; background: var(--surface); outline: none; font-family: inherit; }
        input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent) 14%, transparent); }
        button { cursor: pointer; font-family: inherit; }
        .btn { padding: 11px 20px; background: var(--accent); color: #fff; border: none; border-radius: var(--rs); font-size: 15px; font-weight: 600; }
        .btn:hover { background: var(--accent-h); }
        .sm-btn { padding: 5px 12px; background: none; border: 1px solid var(--border2); border-radius: var(--rs); font-size: 13px; color: var(--text2); }
        .sm-btn:hover { background: var(--border); }
      `}</style>

      {/* ── UNLOCK ── */}
      {stage === 'unlock' && (
        <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: '1.5rem' }}>
          <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--r)', padding: '2.5rem 2rem', width: '100%', maxWidth: 360 }}>
            <div style={{ fontSize: 40, marginBottom: '1.25rem' }}>🔐</div>
            <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>My Vault</h1>
            <p style={{ fontSize: 14, color: 'var(--text2)', marginBottom: '1.75rem' }}>Read-only view · Enter your master password</p>
            <div style={{ marginBottom: '1rem' }}>
              <input
                type="password" placeholder="Master password"
                value={password} onChange={e => setPassword(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && unlock()}
                autoFocus
              />
              {error && <p style={{ fontSize: 13, color: '#a32d2d', marginTop: 6 }}>{error}</p>}
            </div>
            <button className="btn" style={{ width: '100%' }} onClick={unlock}>Unlock</button>
            <p style={{ fontSize: 12, color: 'var(--text3)', textAlign: 'center', marginTop: '1rem' }}>🔒 Read-only. Changes must be made on your PC.</p>
          </div>
        </div>
      )}

      {/* ── LOADING ── */}
      {stage === 'loading' && (
        <div style={{ minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12 }}>
          <div style={{ fontSize: 32 }}>⏳</div>
          <p style={{ color: 'var(--text2)' }}>Decrypting vault…</p>
        </div>
      )}

      {/* ── APP ── */}
      {stage === 'app' && !selected && (
        <div>
          {/* Header */}
          <div style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)', padding: '0 1rem', height: 54, display: 'flex', alignItems: 'center', gap: 10, position: 'sticky', top: 0, zIndex: 50 }}>
            <span style={{ fontSize: 20 }}>🔐</span>
            <span style={{ fontWeight: 700, fontSize: 16 }}>My Vault</span>
            <span style={{ marginLeft: 'auto', fontSize: 12, color: 'var(--text3)', background: 'var(--accent-l)', padding: '3px 10px', borderRadius: 99, color: 'var(--accent)' }}>👁 Read-only</span>
          </div>

          {/* Search */}
          <div style={{ padding: '0.9rem 1rem 0' }}>
            <input type="text" placeholder="🔍  Search…" value={search} onChange={e => setSearch(e.target.value)} />
          </div>

          {/* Category tabs */}
          <div style={{ display: 'flex', gap: 6, padding: '0.75rem 1rem', overflowX: 'auto' }}>
            {[['all','All'], ['app-password','Apps'], ['app-lock','Locks'], ['service','Services'], ['info','Info'], ['other','Other']].map(([k, label]) => (
              <button key={k} onClick={() => setCat(k)} style={{
                padding: '5px 12px', borderRadius: 99, fontSize: 13, fontWeight: cat===k ? 600 : 400, whiteSpace: 'nowrap',
                background: cat===k ? 'var(--accent)' : 'var(--surface)', color: cat===k ? '#fff' : 'var(--text2)',
                border: `1px solid ${cat===k ? 'var(--accent)' : 'var(--border2)'}`, cursor: 'pointer'
              }}>
                {label} <span style={{ opacity: 0.7 }}>({counts[k]})</span>
              </button>
            ))}
          </div>

          {/* Entries */}
          <div style={{ padding: '0 1rem 2rem', display: 'flex', flexDirection: 'column', gap: 8 }}>
            {filtered.length === 0 && (
              <div style={{ textAlign: 'center', padding: '3rem 0', color: 'var(--text3)' }}>
                <div style={{ fontSize: 40, marginBottom: 12 }}>🔐</div>
                <p>No entries found.</p>
              </div>
            )}
            {filtered.map(e => (
              <div key={e.id} onClick={() => setSelected(e)} style={{
                background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--r)',
                padding: '12px 14px', display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer'
              }}>
                <div style={{ width: 38, height: 38, borderRadius: 'var(--rs)', background: CAT_COLORS[e.category] || '#f5f5f4', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18, flexShrink: 0 }}>
                  {CAT_ICONS[e.category] || '📦'}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: 14, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{e.data.name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text2)', marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{e.data.username || e.category}</div>
                </div>
                <span style={{ fontSize: 18, color: 'var(--text3)' }}>›</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── DETAIL VIEW ── */}
      {stage === 'app' && selected && (
        <div>
          <div style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)', padding: '0 1rem', height: 54, display: 'flex', alignItems: 'center', gap: 10, position: 'sticky', top: 0, zIndex: 50 }}>
            <button onClick={() => { setSelected(null); setShowPw(false); }} style={{ background: 'none', border: 'none', fontSize: 22, color: 'var(--accent)', padding: '0 4px' }}>‹</button>
            <span style={{ fontWeight: 600, fontSize: 16, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{selected.data.name}</span>
          </div>

          <div style={{ padding: '1.25rem 1rem', display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
              <div style={{ width: 48, height: 48, borderRadius: 'var(--r)', background: CAT_COLORS[selected.category] || '#f5f5f4', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24 }}>
                {CAT_ICONS[selected.category]}
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: 18 }}>{selected.data.name}</div>
                <div style={{ fontSize: 13, color: 'var(--text2)' }}>{selected.category}</div>
              </div>
            </div>

            {[
              ['Username / email', selected.data.username, 'username'],
              ['URL / App', selected.data.url, 'url'],
              ['Extra field', selected.data.extra, 'extra']
            ].filter(([,v]) => v).map(([label, val, key]) => (
              <div key={key} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--r)', padding: '10px 14px' }}>
                <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text3)', fontWeight: 600, marginBottom: 4 }}>{label}</div>
                <div style={{ fontSize: 14, fontFamily: 'monospace', wordBreak: 'break-all' }}>{val}</div>
                <button className="sm-btn" style={{ marginTop: 8 }} onClick={() => copyText(val, key)}>
                  {copying === key ? '✓ Copied' : '📋 Copy'}
                </button>
              </div>
            ))}

            {/* Password field */}
            {selected.data.password && (
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--r)', padding: '10px 14px' }}>
                <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text3)', fontWeight: 600, marginBottom: 4 }}>
                  {selected.category === 'app-lock' ? 'PIN / code' : 'Password'}
                </div>
                <div style={{ fontSize: 14, fontFamily: 'monospace', wordBreak: 'break-all', letterSpacing: showPw ? 0 : '0.15em' }}>
                  {showPw ? selected.data.password : '•'.repeat(Math.min(selected.data.password.length, 16))}
                </div>
                <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                  <button className="sm-btn" onClick={() => setShowPw(p => !p)}>{showPw ? '🙈 Hide' : '👁 Show'}</button>
                  <button className="sm-btn" onClick={() => copyText(selected.data.password, 'password')}>
                    {copying === 'password' ? '✓ Copied' : '📋 Copy'}
                  </button>
                </div>
              </div>
            )}

            {/* Notes */}
            {selected.data.notes && (
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 'var(--r)', padding: '10px 14px' }}>
                <div style={{ fontSize: 11, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text3)', fontWeight: 600, marginBottom: 4 }}>
                  {selected.category === 'info' ? 'Content / details' : 'Notes'}
                </div>
                <div style={{ fontSize: 14, lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{selected.data.notes}</div>
              </div>
            )}

            <p style={{ fontSize: 12, color: 'var(--text3)', textAlign: 'center', marginTop: 8 }}>
              🔒 Read-only — make changes on your PC
            </p>
          </div>
        </div>
      )}
    </>
  );
}
