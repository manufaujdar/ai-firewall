"""Dependency-free local operator workspace for synthetic scan review."""

CONSOLE_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <meta name="description" content="Local-first research console for reviewing AI Firewall scan decisions.">
  <title>AI Firewall · Local review workspace</title>
  <link rel="stylesheet" href="/assets/console.css">
</head>
<body>
  <a class="skip-link" href="#workspace">Skip to scan workspace</a>
  <header class="site-header">
    <a class="brand" href="/" aria-label="AI Firewall home">
      <svg class="mark" viewBox="0 0 42 42" aria-hidden="true">
        <path d="M21 3 35 9v10c0 9-5.8 16.1-14 20C12.8 35.1 7 28 7 19V9l14-6Z"/>
        <path d="M13 16c5-3 11-3 16 0M12 22c6-3 12-3 18 0M14 28c4-2 10-2 14 0"/>
      </svg>
      <span><strong>AI Firewall</strong><small>Local research framework</small></span>
    </a>
    <nav aria-label="Primary">
      <a href="#workspace">Scan</a><a href="#method">Method</a>
      <a href="https://github.com/manufaujdar/ai-firewall">Source</a>
    </nav>
    <span class="local-badge"><span aria-hidden="true"></span> Local only</span>
  </header>

  <main id="workspace">
    <section class="intro" aria-labelledby="page-title">
      <p class="eyebrow">Research preview · v0.1.1</p>
      <h1 id="page-title">Review information before an AI call.</h1>
      <p class="lede">Inspect a JSON payload through the local real-time privacy graph. Raw content
      is processed ephemerally, never written to audit or history storage, and never forwarded by
      this build. This research framework is not a complete DLP product.</p>
    </section>

    <div class="notice" role="note">
      <strong>Validate before regulated deployment.</strong>
      The current research build is local-only and forwarding is disabled. Do not use production
      regulated data until your organization has completed threat modelling, model validation,
      access control, endpoint enforcement, and legal review.
    </div>

    <section class="panel scan-panel" aria-labelledby="scan-title">
      <div class="section-heading">
        <div><p class="step">01 · Prepare</p><h2 id="scan-title">Payload inspection</h2></div>
        <span id="connection-status" class="status neutral">Not checked</span>
      </div>

      <label for="payload">JSON payload <span>Required</span></label>
      <textarea id="payload" spellcheck="false" aria-describedby="payload-help" placeholder="Paste a JSON value for ephemeral local inspection"></textarea>
      <p id="payload-help" class="help">Only JSON values are supported. Files, images, audio,
      archives, encoded secrets, and streaming frames are not inspected by this prototype.</p>

      <button id="scan" class="primary" type="button">Analyze payload</button>
      <p id="scan-status" class="action-status" aria-live="polite">Ready for a synthetic scan.</p>

      <details>
        <summary>Connection and advanced settings</summary>
        <div class="details-grid">
          <div>
            <label for="key">Local firewall API key <span>Required</span></label>
            <input id="key" type="password" autocomplete="off" placeholder="32+ character local key">
            <p class="help">Held in page memory only. It is never added to browser storage.</p>
          </div>
          <div class="button-stack">
            <button id="policy" class="secondary" type="button">Review policy summary</button>
            <button id="topology" class="secondary" type="button">Inspect runtime topology</button>
            <button id="clear-history" class="quiet" type="button">Clear local history</button>
          </div>
        </div>
      </details>
    </section>

    <section id="results-panel" class="panel results-panel" aria-labelledby="results-title" hidden>
      <div class="section-heading">
        <div><p class="step">02 · Review</p><h2 id="results-title">Inspection result</h2></div>
        <span id="decision" class="decision">—</span>
      </div>
      <div id="scan-summary"><div class="metrics" aria-label="Result summary">
        <div><span>Decision</span><strong id="metric-decision">—</strong></div>
        <div><span>Findings</span><strong id="metric-findings">0</strong></div>
        <div><span>Rules triggered</span><strong id="metric-rules">0</strong></div>
        <div><span>Review gate</span><strong id="metric-gate">Required</strong></div>
      </div>
      <div id="warnings" class="warnings"></div>
      <h3>Real-time privacy events</h3>
      <ol id="event-timeline" class="event-timeline" aria-live="polite"></ol>
      </div>
      <h3>Structured scan result</h3>
      <pre id="result" tabindex="0">No result yet.</pre>
      <div class="result-actions">
        <button id="download" class="secondary" type="button">Download report</button>
        <button id="copy-brief" class="secondary" type="button">Copy review brief</button>
      </div>
      <p class="help">Downloads and copied briefs contain metadata only. The transient structured
      result above is not written to history, local storage, or the server database.</p>
    </section>

    <section class="panel" aria-labelledby="history-title">
      <div class="section-heading">
        <div><p class="step">03 · Review</p><h2 id="history-title">Local metadata history</h2></div>
        <span id="history-count" class="muted">0 saved</span>
      </div>
      <div id="history" class="empty">Enter the local key to load metadata-only history.</div>
    </section>

    <section id="method" class="method" aria-labelledby="method-title">
      <p class="eyebrow">Method and limits</p><h2 id="method-title">Deterministic before probabilistic</h2>
      <div class="method-grid">
        <article><span>1</span><h3>Bound input</h3><p>Reject oversized, malformed, deeply nested,
        or unsupported JSON before it consumes unbounded work.</p></article>
        <article><span>2</span><h3>Inspect locally</h3><p>Apply configured patterns and validators.
        Detector failures become block decisions, not silent passes.</p></article>
        <article><span>3</span><h3>Make uncertainty visible</h3><p>Show findings and limitations for human
        review. The gateway does not claim complete leak prevention.</p></article>
      </div>
    </section>
  </main>

  <footer>
    <div><strong>AI Firewall</strong><p>Local-first, research-only, metadata-safe by design.</p></div>
    <nav aria-label="Project information">
      <a href="https://github.com/manufaujdar/ai-firewall/blob/main/LICENSE">Apache-2.0</a>
      <a href="https://github.com/manufaujdar/ai-firewall/blob/main/SECURITY.md">Security</a>
      <a href="https://github.com/manufaujdar/ai-firewall/blob/main/docs/limitations.md">Limitations</a>
    </nav>
  </footer>
  <script src="/assets/console.js" defer></script>
</body></html>"""

CONSOLE_CSS = r"""
:root{color-scheme:light;--ink:#15231e;--muted:#62706a;--paper:#f6f5ef;--surface:#fffefa;--line:#d9ddd6;--accent:#176b52;--accent-dark:#0d4d3a;--warn:#8a4b12;--warn-bg:#fff5df;--danger:#9c2d25;--danger-bg:#fff0ed;--ok:#236c43;--ok-bg:#edf8f1;--shadow:0 16px 40px rgba(21,35,30,.07)}
[hidden]{display:none!important}*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:6rem}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.55 Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input,textarea{font:inherit}a{color:inherit;text-underline-offset:.2em}.skip-link{position:fixed;left:1rem;top:-5rem;z-index:20;background:var(--ink);color:white;padding:.75rem 1rem;border-radius:.4rem}.skip-link:focus{top:1rem}.site-header{min-height:76px;display:flex;align-items:center;gap:2rem;padding:0 clamp(1rem,5vw,4rem);background:rgba(255,254,250,.95);border-bottom:1px solid var(--line);position:sticky;top:0;z-index:10;backdrop-filter:blur(10px)}.brand{display:flex;align-items:center;gap:.7rem;text-decoration:none;margin-right:auto}.brand span{display:grid;line-height:1.15}.brand small{font-size:.72rem;color:var(--muted);margin-top:.18rem}.mark{width:38px;height:38px}.mark path:first-child{fill:#dfeee8;stroke:var(--accent);stroke-width:1.4}.mark path:last-child{fill:none;stroke:var(--accent);stroke-width:1.3;stroke-linecap:round}.site-header nav{display:flex;gap:1.35rem}.site-header nav a{text-decoration:none;font-size:.9rem;color:#45524d}.local-badge{font-size:.78rem;border:1px solid var(--line);padding:.35rem .62rem;border-radius:999px;white-space:nowrap}.local-badge span{display:inline-block;width:.45rem;height:.45rem;background:var(--ok);border-radius:50%;margin-right:.35rem}main{width:min(1040px,calc(100% - 2rem));margin:0 auto;padding:5rem 0}.intro{max-width:760px;margin-bottom:2rem}.eyebrow,.step{color:var(--accent);font-size:.75rem;font-weight:750;text-transform:uppercase;letter-spacing:.12em;margin:0 0 .6rem}h1{font-family:Georgia,serif;font-size:clamp(2.45rem,7vw,4.75rem);font-weight:500;line-height:1.02;letter-spacing:-.045em;margin:.2rem 0 1.25rem}h2{font-family:Georgia,serif;font-size:clamp(1.7rem,4vw,2.4rem);font-weight:500;letter-spacing:-.025em;margin:0}h3{font-size:1rem;margin:1.2rem 0 .5rem}.lede{font-size:1.15rem;color:#4c5b55;max-width:690px}.notice{background:var(--warn-bg);border:1px solid #ead5a9;border-radius:.65rem;padding:1rem 1.15rem;margin:2rem 0}.notice strong{display:block}.panel{background:var(--surface);border:1px solid var(--line);border-radius:.8rem;padding:clamp(1.15rem,4vw,2rem);box-shadow:var(--shadow);margin:1.25rem 0}.section-heading{display:flex;align-items:start;justify-content:space-between;gap:1rem;margin-bottom:1.5rem}.section-heading .step{margin-bottom:.25rem}.status,.decision{font-size:.78rem;font-weight:700;padding:.35rem .65rem;border-radius:999px;border:1px solid var(--line);white-space:nowrap}.status.ok,.decision.redact{color:var(--ok);background:var(--ok-bg);border-color:#bbddc7}.decision.block{color:var(--danger);background:var(--danger-bg);border-color:#efc4be}.decision.allow{color:var(--ok);background:var(--ok-bg);border-color:#bbddc7}label{display:block;font-weight:700;margin:.8rem 0 .4rem}label span{color:var(--muted);font-weight:500;font-size:.8rem;margin-left:.3rem}textarea,input{width:100%;border:1px solid #bfc7c1;background:white;color:var(--ink);border-radius:.45rem;padding:.8rem}textarea{min-height:215px;resize:vertical;font:14px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}input{min-height:46px}.help,.muted{color:var(--muted);font-size:.84rem}.primary,.secondary,.quiet{border-radius:.4rem;padding:.72rem 1rem;font-weight:700;cursor:pointer}.primary{display:block;width:100%;background:var(--accent);color:white;border:1px solid var(--accent);margin-top:1.4rem}.primary:hover{background:var(--accent-dark)}.secondary{background:white;color:var(--accent-dark);border:1px solid #aebdb6}.quiet{background:transparent;color:#5b6661;border:1px solid transparent}.action-status{text-align:center;color:var(--muted);font-size:.87rem;margin:.55rem 0 0}button:disabled{opacity:.55;cursor:wait}button:focus-visible,a:focus-visible,input:focus-visible,textarea:focus-visible,summary:focus-visible,pre:focus-visible{outline:3px solid #e1a33f;outline-offset:3px}details{margin-top:1.5rem;border-top:1px solid var(--line);padding-top:1rem}summary{font-weight:700;cursor:pointer;width:max-content;max-width:100%}.details-grid{display:grid;grid-template-columns:1fr auto;gap:1.5rem;align-items:end;margin-top:1rem}.button-stack{display:flex;gap:.5rem;flex-wrap:wrap}.metrics{display:grid;grid-template-columns:repeat(4,1fr);border:1px solid var(--line);border-radius:.55rem;overflow:hidden}.metrics div{padding:1rem;border-right:1px solid var(--line)}.metrics div:last-child{border:0}.metrics span{display:block;font-size:.75rem;color:var(--muted);margin-bottom:.3rem}.metrics strong{font-size:1.05rem;text-transform:capitalize}.warnings{margin:1rem 0}.warning{padding:.7rem .85rem;background:var(--warn-bg);border-left:3px solid #d08a2f;margin:.5rem 0;font-size:.9rem}.event-timeline{display:grid;gap:.45rem;padding:0;list-style:none}.event-timeline li{display:flex;justify-content:space-between;gap:1rem;border-left:3px solid var(--accent);background:#f1f6f3;padding:.55rem .7rem;font-size:.86rem}.event-timeline li span:last-child{color:var(--muted)}pre{max-height:370px;overflow:auto;background:#14231e;color:#eaf3ee;border-radius:.55rem;padding:1rem;white-space:pre-wrap;word-break:break-word;font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace}.result-actions{display:flex;gap:.7rem;flex-wrap:wrap}.empty{padding:2rem;text-align:center;color:var(--muted);border:1px dashed #bdc7c0;border-radius:.55rem}.history-list{display:grid;gap:.6rem}.history-item{display:flex;justify-content:space-between;gap:1rem;padding:.8rem 0;border-bottom:1px solid var(--line)}.history-item:last-child{border:0}.history-item strong{text-transform:capitalize}.method{padding:5rem 0 1.5rem}.method>h2{max-width:620px}.method-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-top:2rem}.method article{border-top:2px solid var(--accent);padding-top:1rem}.method article>span{font:1.7rem Georgia,serif;color:#8aa99d}.method article p{color:var(--muted);font-size:.9rem}footer{background:#14231e;color:#e9f0ec;display:flex;justify-content:space-between;gap:2rem;padding:2.5rem clamp(1rem,5vw,4rem)}footer p{font-size:.85rem;color:#aebcb6;margin:.3rem 0}footer nav{display:flex;gap:1.2rem;align-items:center;font-size:.85rem}
@media(max-width:720px){.site-header{min-height:68px;gap:.75rem;padding-block:.75rem}.site-header nav{display:none}.brand small{display:none}main{padding:3rem 0}.metrics{grid-template-columns:1fr 1fr}.metrics div:nth-child(2){border-right:0}.metrics div:nth-child(-n+2){border-bottom:1px solid var(--line)}.details-grid,.method-grid{grid-template-columns:1fr}.button-stack{align-items:start}.button-stack button{width:100%}footer{display:block}footer nav{margin-top:1.5rem;flex-wrap:wrap}h1{font-size:2.7rem}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}*{transition:none!important}}
"""

CONSOLE_JS = r"""
const $ = (selector) => document.querySelector(selector);
let lastRecord = null;

function headers(includeJson = false) {
  const values = {'x-ai-firewall-api-key': $('#key').value};
  if (includeJson) values['content-type'] = 'application/json';
  return values;
}

function setBusy(busy) {
  $('#scan').disabled = busy;
  $('#scan').textContent = busy ? 'Analyzing locally…' : 'Analyze payload';
}

async function jsonResponse(response) {
  try { return await response.json(); }
  catch { return {detail: 'The local service returned a non-JSON response.'}; }
}

function renderTimeline(event) {
  const row = document.createElement('li');
  const phase = document.createElement('strong');
  const status = document.createElement('span');
  phase.textContent = event.phase.replaceAll('_', ' ');
  status.textContent = `${event.status} · ${event.sequence}`;
  row.append(phase, status);
  $('#event-timeline').append(row);
}

async function consumeEventStream(response) {
  if (!response.body) throw new Error('Streaming response unavailable');
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let finalRecord = null;
  while (true) {
    const {value, done} = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), {stream: !done});
    const blocks = buffer.split('\n\n');
    buffer = blocks.pop() || '';
    for (const block of blocks) {
      let eventName = 'message';
      let data = '';
      for (const line of block.split('\n')) {
        if (line.startsWith('event: ')) eventName = line.slice(7);
        if (line.startsWith('data: ')) data += line.slice(6);
      }
      if (!data) continue;
      const parsed = JSON.parse(data);
      if (eventName === 'privacy') renderTimeline(parsed);
      if (eventName === 'result') finalRecord = makeRecord(parsed);
    }
    if (done) break;
  }
  if (!finalRecord) throw new Error('No final inspection result');
  return finalRecord;
}

function makeRecord(envelope) {
  const result = envelope.result;
  return {
    requestId: envelope.request_id,
    timestamp: new Date().toISOString(),
    decision: result.decision,
    findingCount: (result.findings || []).reduce((sum, item) => sum + (item.count || 0), 0),
    rules: [...new Set((result.findings || []).map((item) => item.rule_id))],
    response: result,
  };
}

function warningMessages(result) {
  const warnings = ['Human review is required before any onward use.'];
  if (result.decision === 'block' && !result.findings.length) {
    warnings.push('The default-block policy rejected unmatched content.');
  }
  if (result.decision === 'redact') {
    warnings.push('Review transient sanitized output for residual sensitive context.');
  }
  warnings.push('Files, media, encoding, fragmentation, and streams remain unsupported.');
  return warnings;
}

function renderResult(record) {
  lastRecord = record;
  const result = record.response;
  $('#results-panel').hidden = false;
  $('#scan-summary').hidden = false;
  $('.result-actions').hidden = false;
  $('#decision').textContent = result.decision;
  $('#decision').className = `decision ${result.decision}`;
  $('#metric-decision').textContent = result.decision;
  $('#metric-findings').textContent = String(record.findingCount);
  $('#metric-rules').textContent = String(record.rules.length);
  $('#metric-gate').textContent = 'Human review';
  $('#result').textContent = JSON.stringify(result, null, 2);
  $('#warnings').replaceChildren(...warningMessages(result).map((message) => {
    const item = document.createElement('div');
    item.className = 'warning';
    item.textContent = message;
    return item;
  }));
  $('#results-panel').scrollIntoView({behavior: 'smooth', block: 'start'});
}

function metadataExport(record) {
  return {
    request_id: record.requestId,
    timestamp: record.timestamp,
    decision: record.decision,
    finding_count: record.findingCount,
    rule_ids: record.rules,
    review_gate: 'human_review_required',
    payload_included: false,
  };
}

function makeBrief(record) {
  const metadata = metadataExport(record);
  return `# AI Firewall metadata-only review\n\n- Request: ${metadata.request_id}\n- Captured: ${metadata.timestamp}\n- Decision: ${metadata.decision}\n- Findings: ${metadata.finding_count}\n- Rules: ${metadata.rule_ids.join(', ') || 'none'}\n- Payload persisted: no\n- Review gate: human review required\n\nThis local deterministic result does not prove that content is safe and is not device-wide enforcement.\n`;
}

async function refreshHistory() {
  if (!$('#key').value) return;
  try {
  const response = await fetch('/v1/privacy/history', {headers: headers()});
  if (!response.ok) throw new Error(`History unavailable (${response.status}).`);
  const value = await jsonResponse(response);
  const records = value.items || [];
  $('#history-count').textContent = `${records.length} saved`;
  if (!records.length) {
    $('#history').className = 'empty';
    $('#history').textContent = 'No metadata-only inspection summaries saved.';
    return;
  }
  $('#history').className = 'history-list';
  $('#history').replaceChildren(...records.map((record) => {
    const row = document.createElement('div');
    row.className = 'history-item';
    const left = document.createElement('div');
    const title = document.createElement('strong');
    const detail = document.createElement('div');
    const rules = document.createElement('span');
    title.textContent = record.decision;
    detail.className = 'muted';
    detail.textContent = `${record.finding_count} findings · ${new Date(record.timestamp).toLocaleString()}`;
    rules.className = 'muted';
    rules.textContent = record.rule_ids.join(', ') || 'No matching rules';
    left.append(title, detail);
    row.append(left, rules);
    return row;
  }));
  } catch {
    $('#history-count').textContent = 'Unavailable';
    $('#history').textContent = 'History could not be loaded. Check the local connection and key, then try again.';
  }
}

$('#scan').addEventListener('click', async () => {
  let payload;
  try { payload = JSON.parse($('#payload').value); }
  catch { $('#scan-status').textContent = 'Enter valid JSON before analyzing.'; return; }
  if (!$('#key').value) {
    $('#scan-status').textContent = 'Enter the local API key under advanced settings.';
    $('details').open = true;
    $('#key').focus();
    return;
  }
  setBusy(true);
  $('#event-timeline').replaceChildren();
  $('#scan-status').textContent = 'Running the local privacy graph…';
  try {
    const response = await fetch('/v1/privacy/inspect/stream', {
      method: 'POST', headers: headers(true), body: JSON.stringify({payload}),
    });
    if (!response.ok) throw new Error(`Inspection unavailable (${response.status})`);
    const record = await consumeEventStream(response);
    renderResult(record);
    await refreshHistory();
    $('#connection-status').textContent = 'Local graph active';
    $('#connection-status').className = 'status ok';
    $('#scan-status').textContent = 'Inspection complete. Raw content was not persisted.';
  } catch {
    $('#scan-status').textContent = 'Local inspection failed closed. No cloud request was made.';
    $('#connection-status').textContent = 'Unavailable';
  } finally { setBusy(false); }
});

for (const [id, path, label] of [
  ['policy', '/v1/policy', 'Policy summary'],
  ['topology', '/v1/privacy/topology', 'Runtime topology'],
]) {
  $(`#${id}`).addEventListener('click', async (event) => {
    event.currentTarget.disabled = true;
    $('#scan-status').textContent = `Loading ${label.toLowerCase()}…`;
    try {
      const response = await fetch(path, {headers: headers()});
      if (!response.ok) throw new Error(`Request failed (${response.status}).`);
      const value = await response.json();
      lastRecord = null;
      $('#results-panel').hidden = false;
      $('#scan-summary').hidden = true;
      $('.result-actions').hidden = true;
      $('#decision').className = 'decision';
      $('#decision').textContent = label;
      $('#result').textContent = JSON.stringify(value, null, 2);
      $('#scan-status').textContent = `${label} loaded.`;
      $('#results-panel').scrollIntoView({block: 'start'});
    } catch {
      $('#scan-status').textContent = `${label} unavailable. Check the local connection and API key, then retry.`;
    } finally { $(`#${id}`).disabled = false; }
  });
}

$('#clear-history').addEventListener('click', async () => {
  try {
    const response = await fetch('/v1/privacy/history', {method: 'DELETE', headers: headers()});
    if (!response.ok) throw new Error('History could not be cleared.');
    await refreshHistory();
    $('#scan-status').textContent = 'Local metadata history cleared.';
  } catch { $('#scan-status').textContent = 'History could not be cleared. Check the local connection and key, then retry.'; }
});

$('#download').addEventListener('click', () => {
  if (!lastRecord) return;
  const blob = new Blob([JSON.stringify(metadataExport(lastRecord), null, 2)], {type: 'application/json'});
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = `ai-firewall-metadata-${lastRecord.requestId}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});

$('#copy-brief').addEventListener('click', async () => {
  if (!lastRecord) return;
  try {
    await navigator.clipboard.writeText(makeBrief(lastRecord));
    $('#scan-status').textContent = 'Metadata-only review brief copied.';
  } catch { $('#scan-status').textContent = 'Clipboard access was unavailable.'; }
});
"""
