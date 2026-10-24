"""
Self-contained interactive HTML reports, shared by the tools in this repo.

Intent: give reviewers a single file they can open, filter and share without
installing anything, with the same controls in every tool's report.

render() takes plain data (title, header lines, summary cards, and one or more
tables) and returns a single HTML file: the data is embedded as JSON and drawn
by an inline script, with no external assets. Each table gets:

  * free-text search and a dropdown per filter column (options show counts);
    clicking a cell in a filter column filters on it
  * an optional "show ..." toggle for rows hidden by default (e.g. info)
  * unique counts of chosen columns for the rows currently shown, and an
    optional summary table grouped by one column with the same counts
  * click-to-sort headers (shift-click adds a secondary sort)
  * filter/sort state in the URL fragment, so a view can be bookmarked
  * "Download filtered CSV" for the rows currently shown

Table spec (dict):
  id        short unique id (used in the URL fragment)
  title     heading;  note: optional line under it;  row_label: e.g. "findings"
  columns   [[key, label], ...]; cell values are strings, numbers or lists
  rows      [dict, ...]
  filters   keys with a dropdown
  uniq      [[key, label], ...] columns to count unique values of
  wrap      keys whose text wraps (others stay on one line)
  lines     keys whose list values show one item per line (default: comma-separated)
  badges    {key: {value: css class}}; classes: error, warn, info, ok
  order     {key: [values in sort order]} (e.g. severity)
  sort      initial sort, [[key, 1 | -1], ...]
  hide      {"key": k, "values": [...], "label": "show info"}: hidden until ticked
  by        {"key": k, "label": "By code", "badge": key shown as badge or None}
"""
from __future__ import annotations

import json

TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root { --bg:#fff; --fg:#1d2329; --muted:#5b6670; --line:#d9dee3; --card:#f6f8fa; --hl:#eef3f8;
  --error:#b42318; --error-bg:#fde8e7; --warn:#9a6700; --warn-bg:#fff4d6; --info:#305d9c; --info-bg:#e6effa;
  --ok:#1a7f37; --ok-bg:#dcf5e3; }
@media (prefers-color-scheme: dark) { :root { --bg:#0f1418; --fg:#e3e8ec; --muted:#97a3ad; --line:#2c353d;
  --card:#161d23; --hl:#1b252e; --error:#ff8a80; --error-bg:#3d1714; --warn:#f2c14e; --warn-bg:#3a2e0e;
  --info:#8ab4f8; --info-bg:#14243b; --ok:#6fdc8c; --ok-bg:#12321e; } }
body { background:var(--bg); color:var(--fg); font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
  margin:0 auto; padding:24px 16px; max-width:1600px; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:18px; margin:32px 0 6px; } h3 { font-size:15px; margin:16px 0 6px; }
.muted { color:var(--muted); }
.cards { display:flex; flex-wrap:wrap; gap:10px; margin:12px 0; }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:8px 14px; min-width:96px; }
.card b { display:block; font-size:20px; } .card span { color:var(--muted); font-size:12px; }
.controls { display:flex; flex-wrap:wrap; gap:8px 12px; align-items:end; background:var(--card);
  border:1px solid var(--line); border-radius:8px; padding:10px 12px; margin:8px 0; }
.controls label { display:flex; flex-direction:column; font-size:11px; color:var(--muted); gap:2px; }
.controls label.check { flex-direction:row; align-items:center; gap:6px; font-size:13px; color:var(--fg); }
select, input[type=search], button { font:inherit; font-size:13px; color:var(--fg); background:var(--bg);
  border:1px solid var(--line); border-radius:6px; padding:4px 6px; max-width:220px; }
input[type=search] { width:220px; } button { cursor:pointer; }
.wrap { overflow-x:auto; }
table { border-collapse:collapse; width:100%; margin:6px 0 12px; }
th, td { text-align:left; vertical-align:top; padding:5px 8px; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-weight:600; font-size:12px; white-space:nowrap; cursor:pointer; user-select:none; }
th.sorted::after { content:" \\25B2"; } th.sorted.desc::after { content:" \\25BC"; }
tr:hover td { background:var(--hl); }
td { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px; }
td.nw { white-space:nowrap; } td.f { cursor:pointer; } td.f:hover { text-decoration:underline dotted; }
.badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:12px; font-weight:600;
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }
.error { color:var(--error); background:var(--error-bg); } .warn { color:var(--warn); background:var(--warn-bg); }
.info { color:var(--info); background:var(--info-bg); } .ok { color:var(--ok); background:var(--ok-bg); }
</style></head><body>
<div id="app"></div>
<script id="data" type="application/json">__DATA__</script>
<script>
(() => {
const D = JSON.parse(document.getElementById("data").textContent);
const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const txt = v => Array.isArray(v) ? v.join(", ") : String(v ?? "");
const vals = v => Array.isArray(v) ? v.map(String) : (v === null || v === undefined || v === "" ? [] : [String(v)]);
const card = (n, l) => `<div class="card"><b>${esc(n)}</b><span>${esc(l)}</span></div>`;
const app = document.getElementById("app");
app.innerHTML = `<h1>${esc(D.title)}</h1>` + (D.meta || []).map(m => `<div class="muted">${esc(m)}</div>`).join("") +
  `<div class="cards">${(D.cards || []).map(([v, l]) => card(v, l)).join("")}</div>` + (D.extra_html || "");
const H = new URLSearchParams(location.hash.slice(1));
const tables = [];
function saveHash() {
  // Keep keys that belong to no table (e.g. an extra section's state).
  const p = new URLSearchParams(location.hash.slice(1));
  [...p.keys()].filter(k => tables.some(t => k.startsWith(t.id + "."))).forEach(k => p.delete(k));
  tables.forEach(t => t.save(p));
  history.replaceState(null, "", "#" + p.toString());
}

function makeTable(t) {
  const sec = document.createElement("section");
  app.appendChild(sec);
  const LABEL = Object.fromEntries(t.columns);
  const filters = t.filters || [], wrap = t.wrap || [], badges = t.badges || {}, order = t.order || {};
  const lines = t.lines || [];
  const hide = t.hide, P = t.id + ".";
  const st = {q: "", show: false, f: {}, sort: (t.sort || []).map(x => [...x])};
  filters.forEach(k => { if (H.get(P + k)) st.f[k] = H.get(P + k); });
  st.q = H.get(P + "q") || "";
  st.show = H.get(P + "show") === "1";
  if (H.get(P + "sort")) {
    const s = H.get(P + "sort").split(",").filter(x => LABEL[x.replace(/^-/, "")])
      .map(x => x.startsWith("-") ? [x.slice(1), -1] : [x, 1]);
    if (s.length) st.sort = s;
  }
  const opts = k => {
    const c = {};
    t.rows.forEach(r => vals(r[k]).forEach(v => c[v] = (c[v] || 0) + 1));
    const rk = order[k];
    return Object.keys(c).sort((a, b) => rk ? rk.indexOf(a) - rk.indexOf(b)
      : a.localeCompare(b, undefined, {numeric: true})).map(v => [v, c[v]]);
  };
  sec.innerHTML = `<h2>${esc(t.title)}</h2>` + (t.note ? `<div class="muted">${esc(t.note)}</div>` : "") +
    `<div class="controls"><label>Search<input type="search" data-r="q" placeholder="any text"></label>` +
    filters.map(k => { const o = opts(k);
      return `<label>${esc(LABEL[k] || k)}<select data-k="${esc(k)}"><option value="">All (${o.length})</option>` +
        o.map(([v, n]) => `<option value="${esc(v)}">${esc(v)} (${n})</option>`).join("") + `</select></label>`; }).join("") +
    (hide ? `<label class="check"><input type="checkbox" data-r="show"> ${esc(hide.label)}</label>` : "") +
    `<button data-r="reset">Reset</button><button data-r="csv">Download filtered CSV</button></div>` +
    `<div class="muted" data-r="shown"></div><div class="cards" data-r="uniq"></div>` +
    (t.by ? `<h3>${esc(t.by.label)}</h3><div class="wrap"><table data-r="by"></table></div>` : "") +
    `<div class="muted">Click a header to sort (shift-click adds a secondary sort). ` +
    `Click a cell in a filterable column to filter on it.</div><div class="wrap"><table data-r="tbl"></table></div>`;
  const $ = r => sec.querySelector(`[data-r="${r}"]`);
  const sync = () => {
    $("q").value = st.q;
    if (hide) $("show").checked = st.show;
    sec.querySelectorAll("select[data-k]").forEach(s => s.value = st.f[s.dataset.k] || "");
  };
  const rows = () => {
    const q = st.q.toLowerCase();
    return t.rows.filter(r =>
      (!hide || st.show || st.f[hide.key] || !vals(r[hide.key]).some(v => hide.values.includes(v)))
      && Object.entries(st.f).every(([k, v]) => !v || vals(r[k]).includes(v))
      && (!q || t.columns.some(([k]) => txt(r[k]).toLowerCase().includes(q))));
  };
  const key = (r, k) => {
    if (order[k]) return order[k].indexOf(txt(r[k]));
    return typeof r[k] === "number" ? r[k] : txt(r[k]);
  };
  const cmp = (a, b) => {
    for (const [k, d] of st.sort) {
      const x = key(a, k), y = key(b, k);
      const c = typeof x === "number" && typeof y === "number" ? x - y
        : String(x).localeCompare(String(y), undefined, {numeric: true});
      if (c) return c * d;
    }
    return 0;
  };
  const uniq = (rs, k) => { const s = new Set(); rs.forEach(r => vals(r[k]).forEach(v => s.add(v))); return s.size; };
  const badge = (k, v) => badges[k] && badges[k][v] ? `<span class="badge ${badges[k][v]}">${esc(v)}</span>` : esc(v);
  const cell = (k, v) => {
    const vs = vals(v), f = filters.includes(k) && vs.length === 1;
    const cls = [wrap.includes(k) ? "" : "nw", f ? "f" : ""].filter(Boolean).join(" ");
    return `<td class="${cls}"${f ? ` data-k="${esc(k)}" data-v="${esc(vs[0])}"` : ""}>` +
      (Array.isArray(v) ? v.map(x => badge(k, String(x))).join(lines.includes(k) ? "<br>" : ", ") : badge(k, txt(v))) + `</td>`;
  };
  function render() {
    saveHash();
    const rs = rows().sort(cmp);
    $("shown").textContent = `Showing ${rs.length} of ${t.rows.length} ${t.row_label || "rows"}` +
      (hide && !st.show && !st.f[hide.key] ? ` (${hide.label.replace(/^show /, "")} hidden)` : "");
    $("uniq").innerHTML = card(rs.length, t.row_label || "rows") + (t.uniq || []).map(([k, l]) => card(uniq(rs, k), l)).join("");
    if (t.by) {
      const g = {};
      rs.forEach(r => vals(r[t.by.key]).forEach(v => (g[v] = g[v] || []).push(r)));
      const bk = t.by.badge;
      $("by").innerHTML = `<tr><th>${esc(LABEL[t.by.key] || t.by.key)}</th>` + (bk ? `<th>${esc(LABEL[bk] || bk)}</th>` : "") +
        `<th>${esc(t.row_label || "rows")}</th>` + (t.uniq || []).filter(([k]) => k !== t.by.key)
          .map(([, l]) => `<th>${esc(l)}</th>`).join("") + `</tr>` +
        Object.entries(g).sort((a, b) => (bk ? key(a[1][0], bk) - key(b[1][0], bk) : 0) || b[1].length - a[1].length)
          .map(([v, grp]) => `<tr>${cell(t.by.key, v)}` + (bk ? `<td>${badge(bk, txt(grp[0][bk]))}</td>` : "") +
            `<td>${grp.length}</td>` + (t.uniq || []).filter(([k]) => k !== t.by.key)
              .map(([k]) => `<td>${uniq(grp, k)}</td>`).join("") + `</tr>`).join("");
    }
    const sorted = Object.fromEntries(st.sort);
    $("tbl").innerHTML = `<tr>` + t.columns.map(([k, l]) =>
        `<th data-s="${esc(k)}" class="${k in sorted ? "sorted" + (sorted[k] < 0 ? " desc" : "") : ""}">${esc(l)}</th>`).join("") +
      `</tr>` + rs.map(r => `<tr>` + t.columns.map(([k]) => cell(k, r[k])).join("") + `</tr>`).join("");
  }
  const setFilter = (k, v) => { st.f[k] = v; sync(); render(); };
  sec.addEventListener("change", e => {
    if (e.target.dataset.k) setFilter(e.target.dataset.k, e.target.value);
    else if (e.target.dataset.r === "show") { st.show = e.target.checked; render(); }
  });
  $("q").addEventListener("input", e => { st.q = e.target.value; render(); });
  $("reset").addEventListener("click", () => {
    st.q = ""; st.f = {}; st.show = false; st.sort = (t.sort || []).map(x => [...x]); sync(); render();
  });
  sec.addEventListener("click", e => {
    const th = e.target.closest("th[data-s]");
    if (th) {
      const k = th.dataset.s, i = st.sort.findIndex(([x]) => x === k);
      if (e.shiftKey) { i >= 0 ? st.sort[i][1] *= -1 : st.sort.push([k, 1]); }
      else st.sort = [[k, i === 0 ? -st.sort[0][1] : 1]];
      return render();
    }
    const td = e.target.closest("td.f");
    if (td) setFilter(td.dataset.k, td.dataset.v);
  });
  $("csv").addEventListener("click", () => {
    const q = v => /[",\\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v;
    const lines = [t.columns.map(([k]) => k).join(",")].concat(
      rows().sort(cmp).map(r => t.columns.map(([k]) => q(Array.isArray(r[k]) ? r[k].join("; ") : txt(r[k]))).join(",")));
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([lines.join("\\n")], {type: "text/csv"}));
    a.download = `${t.id}_filtered.csv`;
    a.click();
  });
  sync();
  return {id: t.id, render, save: p => {
    Object.entries(st.f).forEach(([k, v]) => v && p.set(P + k, v));
    if (st.q) p.set(P + "q", st.q);
    if (st.show) p.set(P + "show", "1");
    p.set(P + "sort", st.sort.map(([k, d]) => (d < 0 ? "-" : "") + k).join(","));
  }};
}
D.tables.forEach(t => tables.push(makeTable(t)));
tables.forEach(t => t.render());
})();
</script>
<script>__EXTRA_SCRIPT__</script></body></html>
"""


def render(title: str, *, meta: list[str] | None = None, cards: list[tuple] | None = None,
           tables: list[dict], extra_html: str = "", extra_script: str = "", extra_data=None) -> str:
    """Return the complete HTML document for a report (see the module docstring for the table spec).

    extra_html is inserted between the summary cards and the tables; extra_script runs after
    the tables are drawn and can read `extra_data` as JSON from the element #extra-data
    (a str is taken as JSON text and embedded unchanged).
    """
    data = {"title": title, "meta": meta or [], "cards": [list(c) for c in cards or []], "tables": tables,
            "extra_html": extra_html}
    # Inside <script type=application/json>, only "</" can end the element early.
    payload = json.dumps(data, default=str).replace("</", "<\\/")
    extra = ""
    if extra_data is not None:
        # a str is embedded as-is (already JSON; "</" escaping is idempotent), e.g. when the caller hashes it
        text = extra_data if isinstance(extra_data, str) else json.dumps(extra_data, default=str)
        extra = '<script id="extra-data" type="application/json">' + text.replace("</", "<\\/") + "</script>"
    # Fill each placeholder once, in template order, so data can never be mistaken for one.
    out, rest = [], TEMPLATE
    for marker, value in (("__TITLE__", title.replace("&", "&amp;").replace("<", "&lt;")),
                          ('<div id="app"></div>', '<div id="app"></div>' + extra),
                          ("__DATA__", payload),
                          ("__EXTRA_SCRIPT__", extra_script.replace("</script", "<\\/script"))):
        head, _, rest = rest.partition(marker)
        out += [head, value]
    return "".join(out + [rest])


def write(path, title: str, **kw) -> None:
    """Render a report and write it to `path`."""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render(title, **kw))
