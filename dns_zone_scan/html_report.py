"""Render the report as a self-contained HTML page (same content as the Markdown report)."""

from __future__ import annotations

import html as _html
import re

import markdown

from . import report

CSS = """
:root { --bg:#ffffff; --fg:#1f2328; --muted:#59636e; --border:#d1d9e0; --head:#f6f8fa; --code:#eff1f3;
        --stripe:#fafbfc; --hover:#fff8c5; --accent:#0969da; --red:#d1242f; --orange:#bc4c00; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#0d1117; --fg:#e6edf3; --muted:#9198a1; --border:#3d444d; --head:#151b23; --code:#262c36;
          --stripe:#11161d; --hover:#3a3214; --accent:#4493f8; --red:#ff7b72; --orange:#f0883e; }
}
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
       font:14px/1.5 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
main { padding: 16px 24px 48px; max-width: 100%; }
h1 { font-size: 26px; margin: 8px 0 16px; }
h2 { font-size: 20px; margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid var(--border); }
h3 { font-size: 16px; margin: 20px 0 8px; }
a { color: var(--accent); }
code { background: var(--code); padding: 1px 5px; border-radius: 4px; font-size: 12.5px;
       font-family: ui-monospace, "Cascadia Code", Consolas, monospace; overflow-wrap: anywhere; }
td code { white-space: nowrap; overflow-wrap: normal; }
.wide td:nth-last-child(2) code { white-space: normal; overflow-wrap: anywhere; }
thead tr:has(th:empty:first-child) { display: none; }
.tw:first-of-type td:first-child { white-space: nowrap; width: 1%; }
blockquote { margin: 12px 0; padding: 8px 14px; border-left: 4px solid var(--accent); color: var(--muted);
             background: var(--head); border-radius: 0 6px 6px 0; }
blockquote p { margin: 0; }
.tw { overflow-x: auto; border: 1px solid var(--border); border-radius: 8px; margin: 8px 0 16px; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th, td { padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; text-align: left; }
th { background: var(--head); white-space: nowrap; }
th.sortable { cursor: pointer; user-select: none; }
th.sortable:hover { color: var(--accent); }
th .arrow { display: inline-block; width: 1em; margin-left: 4px; color: var(--muted); font-size: 11px; }
th.sorted .arrow { color: var(--accent); }
tr.filters th { padding: 4px 6px; font-weight: normal; }
tr.filters input { width: 100%; min-width: 60px; padding: 3px 6px; font-size: 12px; border: 1px solid var(--border);
                   border-radius: 4px; background: var(--bg); color: var(--fg); }
tr.filters input.active { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
.tw-meta { display: flex; justify-content: space-between; align-items: center; color: var(--muted);
           font-size: 12px; padding: 4px 10px; border-top: 1px solid var(--border); background: var(--head); }
.tw-meta button, .toolbar button { font-size: 12px; padding: 2px 10px; border: 1px solid var(--border); border-radius: 4px;
           background: var(--bg); color: var(--fg); cursor: pointer; }
tbody tr:nth-child(even) { background: var(--stripe); }
tbody tr:hover { background: var(--hover); }
td { min-width: 70px; }
td:last-child, td:nth-last-child(2) { min-width: 140px; }
.wide td:nth-last-child(2) { min-width: 380px; }
/* grouped (stacked) cells for the wide tables */
.grouped td { min-width: 0; }
.grouped td code { white-space: normal; overflow-wrap: anywhere; }
.grouped td:first-child { min-width: 230px; max-width: 300px; }
.grouped td:nth-child(2) { min-width: 200px; }
.grouped td:nth-child(2) { max-width: 260px; }
.grouped td .main { line-height: 1.45; }
.grouped td .sub { margin-top: 3px; font-size: 12px; line-height: 1.4; }
.grouped .part + .part { margin-left: 10px; }
.grouped .lab { font-size: 10px; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin-right: 4px; }
.grouped td:nth-last-child(2) { min-width: 0; }
.wide.grouped td:nth-last-child(2) { min-width: 300px; }
.subsorts { font-weight: normal; font-size: 11px; margin-top: 2px; }
.subsort { cursor: pointer; color: var(--muted); margin-right: 8px; white-space: nowrap; }
.subsort:hover, .subsort.sorted, .subsort.sorted .arrow { color: var(--accent); }
.subsort .arrow { margin-left: 1px; width: auto; }
details.more { display: inline; }
details.more > summary { display: inline; cursor: pointer; color: var(--accent); font-weight: 600; list-style: none;
                         margin-left: 4px; white-space: nowrap; }
details.more > summary::-webkit-details-marker { display: none; }
details.more > summary:hover { text-decoration: underline; }
details.more[open] > summary { display: block; margin: 2px 0; }
details.more[open] > summary::after { content: " (show less)"; font-weight: normal; }
span[style*="color:red"] { color: var(--red) !important; }
span[style*="color:darkorange"] { color: var(--orange) !important; }
.toolbar { position: sticky; top: 0; z-index: 5; background: var(--bg); padding: 10px 0;
           border-bottom: 1px solid var(--border); display: flex; gap: 12px; align-items: center; flex-wrap: wrap; }
.toolbar input { flex: 1 1 260px; max-width: 420px; padding: 6px 10px; border: 1px solid var(--border);
                 border-radius: 6px; background: var(--bg); color: var(--fg); font-size: 14px; }
.toolbar nav a { margin-right: 10px; font-size: 13px; text-decoration: none; }
.toolbar .count { color: var(--muted); font-size: 12px; }
ul { padding-left: 22px; }
li { margin: 2px 0; }
hr { border: 0; border-top: 1px solid var(--border); margin: 32px 0 16px; }
@media (max-width: 1500px) {
  .grouped td:first-child { min-width: 170px; } .grouped td:nth-child(2) { min-width: 150px; }
  .wide.grouped td:nth-last-child(2) { min-width: 220px; } .grouped th, .grouped td { padding: 6px 7px; }
}
@media (max-width: 700px) { main { padding: 12px 16px 40px; } h1 { font-size: 21px; } }
"""

JS = """
(function () {
  var collator = new Intl.Collator(undefined, {numeric: true, sensitivity: 'base'});
  var globalBox = document.getElementById('filter'), globalCount = document.getElementById('count');
  var tables = [];

  // Wide tables are regrouped so they fit a normal screen: related fields are stacked in one cell.
  // Each group = list of lines, each line = list of original column names shown side by side.
  var LAYOUTS = [
    {needs: 'Insights / action', has: 'Resolves to (live)', groups: [
      {title: 'Record', lines: [['Name'], ['Type', 'Zone value']]},
      {title: 'Resolves to / ICMP', lines: [['Resolves to (live)'], ['ICMP'], ['Reverse DNS']]},
      {title: 'HTTP / HTTPS', lines: [['HTTP'], ['HTTPS']]},
      {title: 'Network', lines: [['Cloud'], ['ASN']]},
      {title: 'Certificate', lines: [['Cert expiry'], ['Certificate issuer']]},
      {title: 'Insights / action', lines: [['Insights / action']]},
      {title: 'Removable?', lines: [['Removable?']]}]},
    {needs: 'Used by', has: 'Whois org', groups: [
      {title: 'IP', lines: [['IP'], ['ICMP', 'TCP']]},
      {title: 'Used by', lines: [['Used by']]},
      {title: 'Cloud / service', lines: [['Cloud / service'], ['Reverse DNS (PTR)']]},
      {title: 'ASN', lines: [['ASN'], ['ASN name']]},
      {title: 'Whois', lines: [['Whois org'], ['Net name', 'Country'], ['Net CIDR']]}]}
  ];
  var SHORT = {'Zone value': 'value', 'Reverse DNS': 'rDNS', 'Reverse DNS (PTR)': 'rDNS', 'Cert expiry': 'expiry',
               'Certificate issuer': 'issuer', 'Resolves to (live)': 'resolves', 'ASN name': 'name',
               'Whois org': 'org', 'Net name': 'net', 'Net CIDR': 'CIDR'};
  function short(n) { return SHORT[n] || n; }

  function norm(el) { return el ? el.textContent.replace(/\\s+/g, ' ').trim() : ''; }

  function regroup(table) {
    var head = table.tHead, body = table.tBodies[0];
    var names = Array.prototype.map.call(head.rows[0].cells, norm);
    var layout = LAYOUTS.filter(function (l) {
      return names.indexOf(l.needs) !== -1 && names.indexOf(l.has) !== -1;
    })[0];
    if (!layout) return null;
    var idx = {}; names.forEach(function (n, i) { idx[n] = i; });
    var tr = document.createElement('tr');
    layout.groups.forEach(function (g) {
      var th = document.createElement('th');
      th.textContent = g.title;
      th._cols = [].concat.apply([], g.lines).filter(function (c) { return c in idx; });
      tr.appendChild(th);
    });
    head.replaceChild(tr, head.rows[0]);
    Array.prototype.slice.call(body.rows).forEach(function (row) {
      var vals = {}, cells = row.cells, out = document.createElement('tr');
      names.forEach(function (n, i) { vals[n] = norm(cells[i]); });
      layout.groups.forEach(function (g, gi) {
        var td = document.createElement('td');
        g.lines.forEach(function (line, li) {
          var parts = line.filter(function (c) { return c in idx && vals[c]; });
          if (!parts.length) return;
          var div = document.createElement('div');
          div.className = li ? 'sub' : 'main';
          parts.forEach(function (c, pi) {
            var span = document.createElement('span');
            span.className = 'part';
            if (li || pi) {   // label everything except the leading value of a group
              var lab = document.createElement('span');
              lab.className = 'lab'; lab.textContent = short(c);
              span.appendChild(lab);
            }
            var v = document.createElement('span');
            v.innerHTML = cells[idx[c]].innerHTML;
            span.appendChild(v);
            div.appendChild(span);
          });
          td.appendChild(div);
        });
        out.appendChild(td);
      });
      out._vals = vals;
      body.replaceChild(out, row);
    });
    return true;
  }

  // "text" contains, "!text" does not contain; several terms separated by spaces must all match
  function matches(text, query) {
    if (!query) return true;
    text = text.toLowerCase();
    return query.toLowerCase().split(/\\s+/).every(function (term) {
      if (!term) return true;
      if (term.charAt(0) === '!' && term.length > 1) return text.indexOf(term.slice(1)) === -1;
      return text.indexOf(term) !== -1;
    });
  }

  function applyAll() {
    var g = globalBox.value.trim(), shownTotal = 0, rowsTotal = 0;
    tables.forEach(function (t) {
      var shown = 0;
      t.rows.forEach(function (r) {
        var ok = matches(r.textContent, g) && t.inputs.every(function (inp, i) {
          return matches(norm(r.cells[i]), inp.value.trim());
        });
        r.style.display = ok ? '' : 'none';
        if (ok) shown++;
      });
      var active = t.inputs.some(function (i) { return i.value.trim(); });
      t.inputs.forEach(function (i) { i.classList.toggle('active', !!i.value.trim()); });
      t.count.textContent = (active || g) ? shown + ' of ' + t.rows.length + ' rows shown' : t.rows.length + ' rows';
      t.clear.style.visibility = active ? 'visible' : 'hidden';
      shownTotal += shown; rowsTotal += t.rows.length;
    });
    globalCount.textContent = g ? shownTotal + ' / ' + rowsTotal + ' rows' : '';
  }

  // keys = sortable things: plain column (by cell text) or a field inside a grouped column
  function sortBy(t, key) {
    var dir = t.sortKey === key ? (t.sortDir === 1 ? -1 : t.sortDir === -1 ? 0 : 1) : 1;
    t.sortKey = dir ? key : null; t.sortDir = dir;
    var rows = dir ? t.rows.slice().sort(function (a, b) {
      var x = key.get(a), y = key.get(b);
      if (!x && y) return 1;            // empty values always last
      if (x && !y) return -1;
      return dir * collator.compare(x, y) || (a._idx - b._idx);
    }) : t.original;
    rows.forEach(function (r) { t.body.appendChild(r); });
    t.keys.forEach(function (k) {
      k.el.classList.toggle('sorted', k === t.sortKey);
      k.arrow.textContent = k === t.sortKey ? (dir === 1 ? '\\u25B2' : '\\u25BC') : '\\u21C5';
    });
  }

  function makeKey(t, el, get) {
    var arrow = document.createElement('span');
    arrow.className = 'arrow'; arrow.textContent = '\\u21C5';
    el.appendChild(arrow);
    var key = {el: el, arrow: arrow, get: get};
    el.addEventListener('click', function (e) { e.stopPropagation(); sortBy(t, key); });
    t.keys.push(key);
    return key;
  }

  document.querySelectorAll('.tw table').forEach(function (table) {
    var head = table.tHead, body = table.tBodies[0];
    if (!head || !body) return;
    if (Array.prototype.every.call(head.rows[0].cells, function (th) { return !norm(th); })) return;  // key/value block
    var grouped = regroup(table);
    if (grouped) table.parentNode.classList.add('grouped');
    var headers = Array.prototype.slice.call(head.rows[0].cells);
    var t = {body: body, sortKey: null, sortDir: 0, inputs: [], keys: []};
    t.rows = Array.prototype.slice.call(body.rows);
    t.rows.forEach(function (r, i) { r._idx = i; });
    t.original = t.rows.slice();

    var filterRow = document.createElement('tr');
    filterRow.className = 'filters';
    headers.forEach(function (th, i) {
      var cols = th._cols;
      if (cols && cols.length > 1) {
        // grouped column: one sort link per field
        var subs = document.createElement('div');
        subs.className = 'subsorts';
        cols.forEach(function (c) {
          var a = document.createElement('span');
          a.className = 'subsort'; a.textContent = short(c); a.title = 'Sort by ' + c;
          subs.appendChild(a);
          makeKey(t, a, function (r) { return r._vals[c]; });
        });
        th.appendChild(subs);
      } else {
        th.classList.add('sortable');
        th.title = 'Click to sort';
        makeKey(t, th, cols ? function (r) { return r._vals[cols[0]]; } : function (r) { return norm(r.cells[i]); });
      }
      var cell = document.createElement('th'), inp = document.createElement('input');
      inp.type = 'search'; inp.placeholder = 'filter'; inp.title = 'Contains text; !text = does not contain';
      inp.addEventListener('input', applyAll);
      cell.appendChild(inp); filterRow.appendChild(cell); t.inputs.push(inp);
    });
    head.appendChild(filterRow);

    var meta = document.createElement('div'); meta.className = 'tw-meta';
    t.count = document.createElement('span');
    t.clear = document.createElement('button'); t.clear.type = 'button'; t.clear.textContent = 'Clear filters';
    t.clear.addEventListener('click', function () { t.inputs.forEach(function (i) { i.value = ''; }); applyAll(); });
    meta.appendChild(t.count); meta.appendChild(t.clear);
    table.parentNode.appendChild(meta);
    tables.push(t);
  });

  globalBox.addEventListener('input', applyAll);
  applyAll();
})();
"""


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", re.sub(r"<[^>]+>", "", text).lower()).strip("-")


def render(scan: dict, md_text: str | None = None) -> str:
    md_text = md_text if md_text is not None else report.render(scan)
    body = markdown.markdown(md_text, extensions=["tables", "sane_lists"], output_format="html")

    # Wrap tables for horizontal scrolling; mark the wide record tables.
    def wrap(m):
        table = m.group(0)
        cls = "tw wide" if "Insights / action" in table else "tw"
        return f'<div class="{cls}">{table}</div>'

    body = re.sub(r"<table>.*?</table>", wrap, body, flags=re.DOTALL)

    # Anchors on h2 for the navigation bar.
    nav = []

    def anchor(m):
        title = m.group(1)
        plain = _html.unescape(re.sub(r"<[^>]+>", "", title))
        sid = _slug(plain)
        nav.append((sid, plain))
        return f'<h2 id="{sid}">{title}</h2>'

    body = re.sub(r"<h2>(.*?)</h2>", anchor, body)
    nav_html = " ".join(f'<a href="#{sid}">{_html.escape(t)}</a>' for sid, t in nav)
    title = f"DNS zone report - {scan['domain']}"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_html.escape(title)}</title>
<style>{CSS}</style>
</head>
<body>
<main>
<div class="toolbar">
  <input id="filter" type="search" placeholder="Filter all tables (name, IP, provider, 'Likely' …; !text excludes)">
  <span id="count" class="count"></span>
  <nav>{nav_html}</nav>
</div>
{body}
</main>
<script>{JS}</script>
</body>
</html>
"""
