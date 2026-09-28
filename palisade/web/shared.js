// Shared helpers. Everything renders through DOM nodes and textContent; no server
// value is ever inserted as HTML.
const $ = s => document.querySelector(s);
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) e.append(k.nodeType ? k : String(k));
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); return node; }
function short(h, n = 12) { return h ? String(h).slice(0, n) : ''; }
async function api(path, opts) {
  const res = await fetch(path, Object.assign({ credentials: 'same-origin' }, opts));
  const type = res.headers.get('content-type') || '';
  const body = type.includes('json') ? await res.json() : await res.text();
  if (!res.ok) { const e = new Error((body && body.error) || res.statusText); e.status = res.status; throw e; }
  return body;
}
function copyButton(value, label = 'Copy') {
  const b = el('button', { class: 'copy', type: 'button', 'aria-label': 'Copy full value' }, label);
  b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(value); b.textContent = 'Copied'; }
    catch { b.textContent = 'Copy failed'; }
    setTimeout(() => (b.textContent = label), 1500);
  });
  return b;
}
function hashLine(value) {
  return el('span', {}, el('code', { class: 'hash', title: value }, short(value)), value ? copyButton(value) : null);
}
function statusEl(kind, text) { return el('span', { class: 'status ' + kind }, text); }
const DECISION_TEXT = {
  answered: 'Answered', flagged: 'Answered, flagged for review',
  blocked_input: 'Blocked before reaching the model', blocked_output: 'Answer blocked before display',
};
function pct(p) { return Math.round(Number(p || 0) * 100) + '%'; }

const CATEGORY_TEXT = {
  weapons_cbrne: 'CBRNE weapons', cyber_offense: 'Offensive cyber', violent_extremism: 'Violent extremism',
  child_safety: 'Child safety', self_harm: 'Self-harm', hate_harassment: 'Hate and harassment',
  prompt_injection: 'Prompt injection', privacy_pii: 'Personal data (PII)', regulated_advice: 'Regulated advice',
};
function catName(id) {
  if (CATEGORY_TEXT[id]) return CATEGORY_TEXT[id];
  const t = String(id).replace(/_/g, ' ');
  return t.charAt(0).toUpperCase() + t.slice(1);
}
