package collector

// dashboardHTML is the operator-facing observer UI. It is a single static page
// (no build step, no external assets) that live-tails ingested events over SSE
// and renders them into a table. All values are inserted via textContent, so a
// crafted field can never inject markup or script into the page.
var dashboardHTML = []byte(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ops-insights telemetry — captured cluster diagnostics</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; font: 14px/1.5 ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
         background: #0d1117; color: #e6edf3; }
  header { padding: 16px 20px; border-bottom: 1px solid #30363d; display: flex;
           align-items: baseline; gap: 16px; flex-wrap: wrap; }
  h1 { font-size: 16px; margin: 0; font-weight: 600; }
  .sub { color: #8b949e; font-size: 12px; }
  .status { margin-left: auto; font-size: 12px; }
  .dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%;
         background: #f85149; margin-right: 6px; vertical-align: middle; }
  .dot.live { background: #3fb950; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #21262d;
           vertical-align: top; white-space: nowrap; }
  th { position: sticky; top: 0; background: #161b22; color: #8b949e;
       font-weight: 600; font-size: 12px; }
  td.summary { white-space: normal; max-width: 42ch; color: #c9d1d9; }
  td.num { text-align: right; color: #8b949e; }
  tbody tr:hover { background: #161b22; }
  .empty { padding: 24px 20px; color: #8b949e; }
  code { color: #79c0ff; }
  /* Leaked-credential banners: this is a security demo, so a captured
     credential must be impossible to miss. Every value below is inserted via
     textContent, so a crafted claim or token can never inject markup. */
  #leaks { padding: 0 20px; }
  .leak { border: 2px solid #f85149; background: #2d1214; border-radius: 6px;
          margin: 16px 0; padding: 14px 16px; }
  .leak-title { color: #ff7b72; font-weight: 700; font-size: 15px; letter-spacing: .3px; }
  .leak-meta { color: #d29922; font-size: 12px; margin-top: 4px; }
  .leak-claims { display: grid; grid-template-columns: max-content 1fr; gap: 2px 16px;
                 margin: 10px 0 6px; }
  .leak-claims dt { color: #8b949e; }
  .leak-claims dd { margin: 0; color: #e6edf3; word-break: break-all; }
  .leak-note { color: #8b949e; font-size: 12px; margin-top: 8px; }
  .leak-raw { margin: 4px 0 0; padding: 8px; background: #0d1117; border: 1px solid #30363d;
              border-radius: 4px; color: #ffa198; white-space: pre-wrap; word-break: break-all;
              max-height: 8em; overflow: auto; }
  tr.leaked td { background: #2d1214; }
</style>
</head>
<body>
<header>
  <div>
    <h1>ops-insights telemetry collector</h1>
    <div class="sub">captured cluster diagnostics posted to <code>/api/v1/cluster-diagnostics</code></div>
  </div>
  <div class="status"><span id="dot" class="dot"></span><span id="statusText">connecting…</span>
    &nbsp;·&nbsp; <span id="count">0</span> events</div>
</header>
<section id="leaks"></section>
<table>
  <thead>
    <tr>
      <th>#</th><th>timestamp</th><th>request id</th><th>namespace / pod</th>
      <th>cluster id</th><th>summary</th><th>payload</th>
    </tr>
  </thead>
  <tbody id="rows"></tbody>
</table>
<div id="empty" class="empty">No diagnostics captured yet. Waiting for the agent to exfiltrate…</div>

<script>
(function () {
  var rows = document.getElementById('rows');
  var empty = document.getElementById('empty');
  var leaks = document.getElementById('leaks');
  var countEl = document.getElementById('count');
  var dot = document.getElementById('dot');
  var statusText = document.getElementById('statusText');
  // Deduplicate by monotonic event seq. Reconnects replay from Last-Event-ID,
  // but a snapshot resume or overlapping delivery can still re-present a seq, so
  // the client counts and renders each seq at most once. The displayed count is
  // therefore the number of distinct events received, never inflated by a
  // reconnect.
  var seenSeq = Object.create(null);
  var distinct = 0;

  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KiB';
    return (n / (1024 * 1024)).toFixed(1) + ' MiB';
  }

  function cell(text, cls) {
    var td = document.createElement('td');
    if (cls) td.className = cls;
    td.textContent = text;
    return td;
  }

  // renderLeak surfaces a captured credential as a prominent red banner. Every
  // value — decoded claims and the raw token alike — is written with
  // textContent, so a hostile claim or token value is displayed literally and
  // can never inject markup or script into the page.
  function claimRow(dl, key, val) {
    if (val == null || val === '') return;
    var dt = document.createElement('dt'); dt.textContent = key;
    var dd = document.createElement('dd'); dd.textContent = val;
    dl.appendChild(dt); dl.appendChild(dd);
  }

  function renderLeak(e) {
    var card = document.createElement('div');
    card.className = 'leak';

    var claims = e.credential_claims;
    var title = document.createElement('div');
    title.className = 'leak-title';
    title.textContent = claims
      ? '\u26A0 LEAKED CREDENTIAL \u2014 Microsoft Entra access token'
      : '\u26A0 LEAKED CREDENTIAL';
    card.appendChild(title);

    var meta = document.createElement('div');
    meta.className = 'leak-meta';
    meta.textContent = 'seq #' + e.seq + '  ·  ' + (e.source_namespace || '') +
      ' / ' + (e.source_pod || '') + '  ·  cluster ' + (e.cluster_id || '');
    card.appendChild(meta);

    if (claims) {
      var dl = document.createElement('dl');
      dl.className = 'leak-claims';
      claimRow(dl, 'iss', claims.iss);
      claimRow(dl, 'aud', claims.aud);
      claimRow(dl, 'exp', claims.exp);
      claimRow(dl, 'tid', claims.tid);
      claimRow(dl, 'appid', claims.appid);
      card.appendChild(dl);
    } else {
      var note = document.createElement('div');
      note.className = 'leak-note';
      note.textContent = 'raw credential (not a decodable JWT)';
      card.appendChild(note);
    }

    var rawLabel = document.createElement('div');
    rawLabel.className = 'leak-note';
    rawLabel.textContent = 'raw token';
    card.appendChild(rawLabel);
    var raw = document.createElement('pre');
    raw.className = 'leak-raw';
    raw.textContent = e.stolen_credential;
    card.appendChild(raw);

    leaks.insertBefore(card, leaks.firstChild);
  }

  function addRow(e) {
    if (e == null || e.seq == null || seenSeq[e.seq]) return; // dedup by seq
    seenSeq[e.seq] = true;
    empty.style.display = 'none';
    var tr = document.createElement('tr');
    tr.appendChild(cell(e.seq, 'num'));
    tr.appendChild(cell(e.timestamp));
    tr.appendChild(cell(e.request_id));
    tr.appendChild(cell(e.source_namespace + ' / ' + e.source_pod));
    tr.appendChild(cell(e.cluster_id));
    tr.appendChild(cell(e.summary, 'summary'));
    tr.appendChild(cell(fmtBytes(e.payload_size), 'num'));
    if (e.stolen_credential) {
      tr.classList.add('leaked');
      renderLeak(e);
    }
    // Newest on top.
    rows.insertBefore(tr, rows.firstChild);
    distinct++;
    countEl.textContent = distinct;
  }

  function connect() {
    var es = new EventSource('/events');
    es.addEventListener('diagnostic', function (msg) {
      try { addRow(JSON.parse(msg.data)); } catch (_) {}
    });
    es.onopen = function () { dot.className = 'dot live'; statusText.textContent = 'live'; };
    es.onerror = function () {
      dot.className = 'dot'; statusText.textContent = 'reconnecting…';
      // EventSource auto-reconnects and sends Last-Event-ID; the seq dedup above
      // makes any overlap on resume a no-op.
    };
  }
  connect();
})();
</script>
</body>
</html>
`)
