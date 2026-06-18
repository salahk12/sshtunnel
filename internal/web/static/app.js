"use strict";
const BASE = window.BASE || "";
const API = BASE + "/api";
const $ = (s, r = document) => r.querySelector(s);
const el = (t, a = {}, ...kids) => {
  const e = document.createElement(t);
  for (const k in a) {
    if (k === "class") e.className = a[k];
    else if (k === "html") e.innerHTML = a[k];
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), a[k]);
    else if (a[k] != null) e.setAttribute(k, a[k]);
  }
  for (const c of kids.flat()) if (c != null) e.append(c.nodeType ? c : document.createTextNode(c));
  return e;
};

// req: low-level call to any api base. `api` targets the local master/auth API.
async function req(base, method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(base + path, opt);
  let data = null;
  try { data = await r.json(); } catch (_) {}
  if (!r.ok) throw new Error((data && data.error) || ("HTTP " + r.status));
  return data;
}
const api = (m, p, b) => req(API, m, p, b);
// nodeApi: base for managing a remote node's tunnels through the master proxy.
const nodeApi = (id) => `${API}/nodes/${id}/proxy`;

function toast(msg, bad) {
  const t = el("div", { class: "toast" }, msg);
  if (bad) t.style.borderColor = "var(--bad)";
  document.body.append(t);
  setTimeout(() => t.remove(), 3400);
}
function fmtBytes(n) {
  n = Number(n) || 0;
  const u = ["B", "KB", "MB", "GB", "TB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return n.toFixed(i ? 1 : 0) + " " + u[i];
}
const fmtRate = (n) => fmtBytes(n) + "/s";
const stat = (k, v) => el("div", { class: "stat" }, el("div", { class: "k" }, k), el("div", { class: "v" }, String(v)));

let CIPHERS = [];
let SESSION = {};
const app = () => $("#app");

// ---------- theme ----------
function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("sshtp-theme", t); } catch (_) {}
}
function curTheme() { return document.documentElement.dataset.theme || "dark"; }
applyTheme((() => { try { return localStorage.getItem("sshtp-theme"); } catch (_) { return null; } })() || "dark");

// ---------- boot ----------
async function boot() {
  try { SESSION = await api("GET", "/session"); } catch (e) { return renderError(e.message); }
  if (SESSION.needs_setup) return renderSetup();
  if (!SESSION.authenticated) return renderLogin();
  try { CIPHERS = await api("GET", "/ciphers"); } catch (_) {}
  renderApp(SESSION.master_enabled ? "central" : "local");
}
function renderError(m) {
  app().innerHTML = "";
  app().append(el("div", { class: "center" }, el("div", { class: "card" }, "خطا: " + m)));
}

// ---------- auth screens ----------
function authScreen(title, btnLabel, onSubmit, extra) {
  app().innerHTML = "";
  const errBox = el("div", { class: "err hidden" });
  const u = el("input", { placeholder: "نام کاربری", autocomplete: "username" });
  const p = el("input", { type: "password", placeholder: "رمز عبور", autocomplete: "current-password" });
  const submit = async () => {
    errBox.classList.add("hidden");
    try { await onSubmit(u.value.trim(), p.value); }
    catch (e) { errBox.textContent = e.message; errBox.classList.remove("hidden"); }
  };
  p.addEventListener("keydown", (e) => { if (e.key === "Enter") submit(); });
  app().append(el("div", { class: "center" },
    el("div", { class: "card loginbox" },
      el("h2", {}, title),
      extra ? el("p", { class: "muted" }, extra) : null,
      errBox,
      el("div", { class: "field" }, el("label", {}, "نام کاربری"), u),
      el("div", { class: "field" }, el("label", {}, "رمز عبور"), p),
      el("button", { style: "width:100%", onclick: submit }, btnLabel))));
}
function renderLogin() {
  authScreen("ورود به پنل", "ورود", async (user, pass) => {
    await api("POST", "/login", { username: user, password: pass }); boot();
  });
}
function renderSetup() {
  authScreen("راه‌اندازی اولیه", "ایجاد حساب مدیر", async (user, pass) => {
    if (pass.length < 6) throw new Error("رمز عبور حداقل ۶ کاراکتر");
    await api("POST", "/setup", { username: user, password: pass }); boot();
  }, "اولین بار است که وارد می‌شوید. یک نام کاربری و رمز عبور مدیر بسازید.");
}

// ---------- app shell ----------
let pollTimer = null;
function setPoll(fn, ms) { if (pollTimer) clearInterval(pollTimer); pollTimer = setInterval(fn, ms); }
function renderApp(tab, arg) {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  app().innerHTML = "";
  const cur = tab === "node" ? "central" : tab;
  const navBtn = (id, label) => el("button", { class: cur === id ? "active" : "", onclick: () => renderApp(id) }, label);
  const nav = el("nav", {});
  if (SESSION.master_enabled) {
    nav.append(navBtn("central", "🖧 نودها (مرکزی)"));
    nav.append(navBtn("local", "تانل‌های این سرور"));
  } else {
    nav.append(navBtn("local", "تانل‌ها"));
  }
  nav.append(navBtn("settings", "تنظیمات"));
  const themeBtn = el("button", { class: "icon-btn ghost", title: "تغییر تم" });
  const setIcon = () => themeBtn.textContent = curTheme() === "dark" ? "☀" : "🌙";
  themeBtn.addEventListener("click", () => { applyTheme(curTheme() === "dark" ? "light" : "dark"); setIcon(); });
  setIcon();
  nav.append(themeBtn);
  nav.append(el("button", { class: "ghost", onclick: logout }, "خروج"));
  app().append(el("header", {}, el("div", { class: "logo" }, "🔒 SSH Tunnel Panel"), nav));
  const m = el("main"); app().append(m);

  if (tab === "central") viewCentral(m);
  else if (tab === "node") viewNodeDetail(m, arg);
  else if (tab === "settings") viewSettings(m);
  else viewLocalTunnels(m);
}
async function logout() { try { await api("POST", "/logout"); } catch (_) {} renderLogin(); }

// ---------- central dashboard (nodes) ----------
const nodeSample = {};
function nodeRate(n) {
  const s = n.summary || {};
  const now = Date.now() / 1000, prev = nodeSample[n.id];
  nodeSample[n.id] = { in: s.bytes_in || 0, out: s.bytes_out || 0, t: now };
  if (!prev) return { ri: 0, ro: 0 };
  const dt = Math.max(now - prev.t, 0.5);
  return { ri: Math.max(0, ((s.bytes_in || 0) - prev.in) / dt), ro: Math.max(0, ((s.bytes_out || 0) - prev.out) / dt) };
}

async function viewCentral(m) {
  m.append(el("div", { class: "toolbar" },
    el("div", {}, el("h2", {}, "داشبورد مرکزی"), el("div", { class: "muted" }, "مدیریت همه‌ی سرورهای ایران (نودها)")),
    el("button", { onclick: openNodeForm }, "+ افزودن نود")));
  const grid = el("div", { class: "tlist" }, el("div", { class: "muted" }, "در حال بارگذاری…"));
  m.append(grid);

  const refresh = async () => {
    let nodes;
    try { nodes = await api("GET", "/nodes"); } catch (e) { return; }
    grid.innerHTML = "";
    if (!nodes.length) { grid.append(el("div", { class: "card muted" }, "هنوز نودی اضافه نکرده‌اید. روی «افزودن نود» بزنید.")); return; }
    let aIn = 0, aOut = 0, aTun = 0, aAct = 0, online = 0;
    for (const n of nodes) { const s = n.summary || {}; aIn += s.bytes_in || 0; aOut += s.bytes_out || 0; aTun += s.tunnels || 0; aAct += s.active_tunnels || 0; if (s.online) online++; }
    grid.append(el("div", { class: "card", style: "margin-bottom:4px" },
      el("div", { class: "stats" },
        stat("نودهای آنلاین", `${online}/${nodes.length}`),
        stat("کل تانل‌ها", aTun), stat("تانل‌های فعال", aAct),
        stat("مجموع ورودی", fmtBytes(aIn)), stat("مجموع خروجی", fmtBytes(aOut)))));
    for (const n of nodes) grid.append(nodeCard(n, refresh));
  };
  await refresh();
  setPoll(refresh, 3000);
}

function nodeCard(n, refresh) {
  const s = n.summary || {};
  const r = nodeRate(n);
  const badge = s.online
    ? el("span", { class: "badge b-ok" }, "آنلاین")
    : el("span", { class: "badge b-bad" }, "آفلاین" + (s.error ? " · " + s.error : ""));
  return el("div", { class: "tcard" },
    el("div", {},
      el("div", {}, el("span", { class: "name" }, n.name), " ", badge, n.local ? el("span", { class: "badge b-off", style: "margin-inline-start:6px" }, "محلی") : null),
      el("div", { class: "sub" }, n.base_url),
      el("div", { class: "stats" },
        stat("تانل‌ها", `${s.active_tunnels || 0}/${s.tunnels || 0} فعال`),
        stat("ورودی", fmtRate(r.ri)), stat("خروجی", fmtRate(r.ro)),
        stat("مجموع ورودی", fmtBytes(s.bytes_in || 0)),
        stat("مجموع خروجی", fmtBytes(s.bytes_out || 0)),
        stat("اتصالات", s.conns || 0))),
    el("div", { class: "actions" },
      el("button", { class: "sm", onclick: () => renderApp("node", n) }, "مدیریت تانل‌ها"),
      n.local ? null : el("button", { class: "danger sm", onclick: () => delNode(n, refresh) }, "حذف نود")));
}

async function delNode(n, refresh) {
  if (!confirm(`حذف نود «${n.name}» از داشبورد؟ (تانل‌های روی خود نود حذف نمی‌شوند)`)) return;
  try { await api("DELETE", "/nodes/" + n.id); toast("حذف شد"); refresh(); }
  catch (e) { toast(e.message, true); }
}

function openNodeForm() {
  const overlay = el("div", { class: "overlay", onclick: (e) => { if (e.target === overlay) overlay.remove(); } });
  const errBox = el("div", { class: "err hidden" });
  const name = el("input", { placeholder: "مثلاً سرور تهران ۱" });
  const url = el("input", { placeholder: "http://IP:2095/webpath", style: "direction:ltr;text-align:left" });
  const token = el("input", { placeholder: "node token", style: "direction:ltr;text-align:left" });
  const save = async () => {
    errBox.classList.add("hidden");
    const btn = $("#nbtn", overlay); btn.disabled = true; btn.textContent = "در حال بررسی اتصال…";
    try {
      await api("POST", "/nodes", { name: name.value.trim(), base_url: url.value.trim(), token: token.value.trim() });
      overlay.remove(); toast("نود اضافه شد"); renderApp("central");
    } catch (e) { errBox.textContent = e.message; errBox.classList.remove("hidden"); btn.disabled = false; btn.textContent = "افزودن"; }
  };
  overlay.append(el("div", { class: "modal" },
    el("h3", {}, "افزودن نود (سرور ایران)"),
    errBox,
    el("div", { class: "field" }, el("label", {}, "نام نود"), name),
    el("div", { class: "field" }, el("label", {}, "آدرس پنل نود (با web path)"), url),
    el("div", { class: "field" }, el("label", {}, "توکن نود"), token),
    el("p", { class: "muted" }, "توکن را روی سرور نود با دستور ‎sshtunnel-panel node-token‎ یا از خروجی نصب بگیرید."),
    el("div", { style: "display:flex;gap:8px;justify-content:flex-end;margin-top:8px" },
      el("button", { class: "ghost", onclick: () => overlay.remove() }, "انصراف"),
      el("button", { id: "nbtn", onclick: save }, "افزودن"))));
  document.body.append(overlay);
}

// ---------- node detail = manage that node's tunnels ----------
function viewNodeDetail(m, node) {
  m.append(el("div", { class: "toolbar" },
    el("div", {},
      el("button", { class: "ghost sm", onclick: () => renderApp("central"), style: "margin-bottom:8px" }, "→ بازگشت به نودها"),
      el("h2", {}, "تانل‌های نود: " + node.name),
      el("div", { class: "muted", style: "direction:ltr;text-align:right" }, node.base_url)),
    el("button", { onclick: () => openTunnelForm(nodeApi(node.id), null, () => renderApp("node", node)) }, "+ افزودن تانل")));
  const list = el("div", { class: "tlist" }); m.append(list);
  mountTunnelList(list, nodeApi(node.id), "n" + node.id);
}

// ---------- local tunnels ----------
function viewLocalTunnels(m) {
  m.append(el("div", { class: "toolbar" },
    el("div", {}, el("h2", {}, "تانل‌های این سرور"), el("div", { class: "muted" }, "تانل‌های SSH اجراشده روی همین سرور")),
    el("button", { onclick: () => openTunnelForm(API, null, () => renderApp("local")) }, "+ افزودن تانل")));
  const list = el("div", { class: "tlist" }); m.append(list);
  mountTunnelList(list, API, "local");
}

// ---------- shared tunnel list (works for local API or a node proxy) ----------
const sampleStore = {};
function tunnelRate(ns, t) {
  const st = t.status && t.status.stat;
  if (!st) return { ri: 0, ro: 0 };
  const key = ns + ":" + t.id, now = Date.now() / 1000, prev = sampleStore[key];
  sampleStore[key] = { in: st.bytes_in, out: st.bytes_out, t: now };
  if (!prev) return { ri: 0, ro: 0 };
  const dt = Math.max(now - prev.t, 0.5);
  return { ri: Math.max(0, (st.bytes_in - prev.in) / dt), ro: Math.max(0, (st.bytes_out - prev.out) / dt) };
}
function statusBadge(t) {
  const a = t.status ? t.status.active : "";
  if (!t.enabled) return el("span", { class: "badge b-off" }, "غیرفعال");
  if (a === "active") {
    const st = t.status.stat;
    if (st && st.connected_workers === 0) return el("span", { class: "badge b-warn" }, "در حال اتصال");
    return el("span", { class: "badge b-ok" }, "فعال");
  }
  if (a === "failed") return el("span", { class: "badge b-bad" }, "خطا");
  if (a === "activating") return el("span", { class: "badge b-warn" }, "راه‌اندازی");
  return el("span", { class: "badge b-bad" }, "متوقف");
}
async function mountTunnelList(list, apiBase, ns) {
  const refresh = async () => {
    let ts;
    try { ts = await req(apiBase, "GET", "/tunnels"); }
    catch (e) { list.innerHTML = ""; list.append(el("div", { class: "card", style: "color:var(--bad)" }, "نود در دسترس نیست: " + e.message)); return; }
    list.innerHTML = "";
    if (!ts.length) { list.append(el("div", { class: "card muted" }, "هنوز تانلی ساخته نشده.")); return; }
    for (const t of ts) list.append(tunnelCard(t, apiBase, ns, refresh));
  };
  list.innerHTML = ""; list.append(el("div", { class: "muted" }, "در حال بارگذاری…"));
  await refresh();
  setPoll(refresh, 2500);
}
function tunnelCard(t, apiBase, ns, refresh) {
  const st = t.status && t.status.stat;
  const r = tunnelRate(ns, t);
  const fwd = (t.forwards || []).map(f => `${f.listen_port}→${f.remote_addr}:${f.remote_port}`).join("، ");
  const act = async (action) => {
    try { await req(apiBase, "POST", `/tunnels/${t.id}/action`, { action }); toast("انجام شد"); refresh(); }
    catch (e) { toast(e.message, true); }
  };
  return el("div", { class: "tcard" },
    el("div", {},
      el("div", {}, el("span", { class: "name" }, t.name), " ", statusBadge(t)),
      el("div", { class: "sub" }, `${t.username}@${t.remote_host}:${t.remote_port} · ${fwd}`),
      el("div", { class: "stats" },
        stat("ورودی (دانلود)", fmtRate(r.ri)),
        stat("خروجی (آپلود)", fmtRate(r.ro)),
        stat("مجموع ورودی", fmtBytes(st ? st.bytes_in : 0)),
        stat("مجموع خروجی", fmtBytes(st ? st.bytes_out : 0)),
        stat("اتصالات", st ? st.active_conns : 0),
        stat("ورکرها", st ? `${st.connected_workers}/${st.total_workers}` : `0/${t.workers}`),
        stat("رمزنگاری", t.cipher || "پیش‌فرض"))),
    el("div", { class: "actions" },
      el("button", { class: "ghost sm", onclick: () => openDetail(apiBase, t.id) }, "جزئیات"),
      t.enabled
        ? el("button", { class: "ghost sm", onclick: () => act("stop") }, "توقف")
        : el("button", { class: "sm", onclick: () => act("start") }, "شروع"),
      el("button", { class: "ghost sm", onclick: () => act("restart") }, "ری‌استارت"),
      el("button", { class: "ghost sm", onclick: () => openTunnelForm(apiBase, t, refresh) }, "ویرایش"),
      el("button", { class: "danger sm", onclick: () => delTunnel(apiBase, t, refresh) }, "حذف")));
}
async function delTunnel(apiBase, t, refresh) {
  if (!confirm(`حذف تانل «${t.name}»؟ سرویس systemd آن هم حذف می‌شود.`)) return;
  try { await req(apiBase, "DELETE", "/tunnels/" + t.id); toast("حذف شد"); refresh(); }
  catch (e) { toast(e.message, true); }
}

// ---------- add / edit tunnel form ----------
function openTunnelForm(apiBase, t, onSaved) {
  const isEdit = !!t; t = t || {};
  const fwds = (t.forwards && t.forwards.length) ? t.forwards.map(x => ({ ...x }))
    : [{ listen_addr: "0.0.0.0", listen_port: 443, remote_addr: "127.0.0.1", remote_port: 443 }];
  const overlay = el("div", { class: "overlay", onclick: (e) => { if (e.target === overlay) overlay.remove(); } });
  const errBox = el("div", { class: "err hidden" });
  const f = {};
  const inp = (key, val, attrs = {}) => (f[key] = el("input", { value: val ?? "", ...attrs }));
  const cipherSel = el("select", {}, el("option", { value: "" }, "پیش‌فرض (امن‌ترین)"),
    ...CIPHERS.map(c => el("option", { value: c, selected: t.cipher === c ? "1" : null }, c)));
  f.cipher = cipherSel;
  const authSel = el("select", {},
    el("option", { value: "password", selected: (!t.auth_method || t.auth_method === "password") && !isEdit ? "1" : null }, "آیپی + یوزرنیم + پسورد"),
    el("option", { value: "key", selected: isEdit ? "1" : null }, "آیپی + یوزرنیم + SSH Key"));
  f.auth = authSel;
  const pwField = el("div", { class: "field" }, el("label", {}, isEdit ? "رمز سرور (برای نصب مجدد کلید)" : "رمز سرور خارج"),
    inp("password", "", { type: "password", placeholder: isEdit ? "خالی = بدون تغییر" : "" }));
  const keyField = el("div", { class: "field hidden" }, el("label", {}, "کلید خصوصی SSH (متن کامل PEM)"),
    (f.private_key = el("textarea", { rows: 5, placeholder: isEdit ? "خالی = استفاده از کلید قبلی" : "-----BEGIN OPENSSH PRIVATE KEY-----", style: "width:100%;font-family:monospace;direction:ltr;padding:10px;border-radius:8px;background:var(--bg);color:var(--txt);border:1px solid var(--border)" })));
  const syncAuth = () => { const k = authSel.value === "key"; keyField.classList.toggle("hidden", !k); pwField.classList.toggle("hidden", k); };
  authSel.addEventListener("change", syncAuth);

  const fwdWrap = el("div", {});
  const blank = () => ({ listen_addr: "0.0.0.0", listen_port: 0, remote_addr: "127.0.0.1", remote_port: 0 });
  const fwdCell = (label, fw, key, type = "number") => {
    const i = el("input", { type, value: fw[key] ?? "" });
    i.addEventListener("input", () => { fw[key] = type === "number" ? parseInt(i.value || "0") : i.value; });
    return el("div", { class: "field" }, el("label", {}, label), i);
  };
  const renderFwds = () => {
    fwdWrap.innerHTML = "";
    fwds.forEach((fw, i) => fwdWrap.append(el("div", { class: "fwd-row" },
      fwdCell("پورت محلی", fw, "listen_port"), fwdCell("آدرس مقصد", fw, "remote_addr", "text"), fwdCell("پورت مقصد", fw, "remote_port"),
      el("button", { class: "ghost sm", onclick: () => { fwds.splice(i, 1); if (!fwds.length) fwds.push(blank()); renderFwds(); } }, "✕"))));
  };
  renderFwds();

  // Mode selector (local vs reverse) + reverse-only fields.
  const modeSel = el("select", {},
    el("option", { value: "local", selected: (!t.mode || t.mode === "local") ? "1" : null }, "Local — ایران به خارج وصل می‌شود (پیش‌فرض)"),
    el("option", { value: "reverse", selected: t.mode === "reverse" ? "1" : null }, "Reverse — خارج به ایران وصل می‌شود (ایران خروجی نمی‌زند)"));
  f.mode = modeSel;
  const revBox = el("div", { class: t.mode === "reverse" ? "" : "hidden" },
    el("hr"),
    el("p", { class: "muted", style: "margin-top:0" }, "ریورس: «سرور خارج» جایی است که کانکتور نصب می‌شود؛ این سرور ایران آدرس عمومی‌اش را می‌دهد تا خارج به آن وصل شود. در پورت‌فورواردها: «پورت محلی» = پورتی که روی ایران باز می‌شود، «مقصد» = مقصدی که از دید سرور خارج در دسترس است."),
    el("div", { class: "row" },
      el("div", { class: "field" }, el("label", {}, "آیپی عمومی این سرور (ایران)"), inp("iran_host", t.iran_host, { placeholder: "آی‌پی عمومی ایران" })),
      el("div", { class: "field" }, el("label", {}, "پورت SSH ایران"), inp("iran_ssh_port", t.iran_ssh_port || 22, { type: "number" })),
      el("div", { class: "field" }, el("label", {}, "یوزر ایران"), inp("iran_user", t.iran_user || "root"))));
  modeSel.addEventListener("change", () => revBox.classList.toggle("hidden", modeSel.value !== "reverse"));

  const save = async () => {
    errBox.classList.add("hidden");
    const body = {
      name: f.name.value.trim(), mode: f.mode.value,
      iran_host: f.iran_host.value.trim(), iran_ssh_port: parseInt(f.iran_ssh_port.value || "22"), iran_user: f.iran_user.value.trim(),
      remote_host: f.remote_host.value.trim(),
      remote_port: parseInt(f.remote_port.value || "22"), username: f.username.value.trim(),
      auth_method: authSel.value, password: f.password.value, private_key: f.private_key.value,
      cipher: cipherSel.value, workers: parseInt(f.workers.value || "1"), compression: f.compression.checked,
      server_alive_interval: parseInt(f.sai.value || "30"), server_alive_count_max: parseInt(f.sacm.value || "3"),
      buffer_size: parseInt(f.buffer_size.value || "0"), socket_buffer: parseInt(f.socket_buffer.value || "0"),
      disable_nodelay: f.disable_nodelay.checked, mss: parseInt(f.mss.value || "0"),
      forwards: fwds, enabled: f.enabled.checked,
    };
    const btn = $("#saveBtn", overlay); btn.disabled = true; btn.textContent = "در حال اتصال به سرور…";
    try {
      if (isEdit) await req(apiBase, "PUT", "/tunnels/" + t.id, body);
      else await req(apiBase, "POST", "/tunnels", body);
      overlay.remove(); toast("ذخیره شد"); if (onSaved) onSaved();
    } catch (e) { errBox.textContent = e.message; errBox.classList.remove("hidden"); btn.disabled = false; btn.textContent = "ذخیره"; }
  };
  function checkbox(key, label, checked) {
    const c = el("input", { type: "checkbox", style: "width:auto" }); c.checked = !!checked; f[key] = c;
    return el("div", { class: "field", style: "display:flex;align-items:center;gap:8px;flex:1" }, c, el("label", { style: "margin:0" }, label));
  }
  overlay.append(el("div", { class: "modal" },
    el("h3", {}, isEdit ? "ویرایش تانل" : "افزودن تانل جدید"),
    errBox,
    el("div", { class: "field" }, el("label", {}, "نام تانل"), inp("name", t.name, { placeholder: "مثلاً تانل 443" })),
    el("div", { class: "field" }, el("label", {}, "نوع تانل"), modeSel),
    revBox,
    el("div", { class: "row" },
      el("div", { class: "field" }, el("label", {}, "آیپی سرور خارج"), inp("remote_host", t.remote_host, { placeholder: "1.2.3.4" })),
      el("div", { class: "field" }, el("label", {}, "پورت SSH"), inp("remote_port", t.remote_port || 22, { type: "number" })),
      el("div", { class: "field" }, el("label", {}, "یوزرنیم"), inp("username", t.username || "root"))),
    el("div", { class: "field" }, el("label", {}, "روش احراز هویت"), authSel),
    pwField, keyField, el("hr"),
    el("label", {}, "پورت‌فورواردها (تانل ترافیک)"), fwdWrap,
    el("button", { class: "ghost sm", onclick: () => { fwds.push(blank()); renderFwds(); } }, "+ افزودن پورت"),
    el("hr"),
    el("div", { class: "row" },
      el("div", { class: "field" }, el("label", {}, "نوع رمزنگاری"), cipherSel),
      el("div", { class: "field" }, el("label", {}, "تعداد ورکر"), inp("workers", t.workers || 1, { type: "number", min: 1, max: 16 }))),
    el("div", { class: "row" },
      el("div", { class: "field" }, el("label", {}, "ServerAliveInterval (ثانیه)"), inp("sai", t.server_alive_interval || 30, { type: "number" })),
      el("div", { class: "field" }, el("label", {}, "ServerAliveCountMax"), inp("sacm", t.server_alive_count_max || 3, { type: "number" }))),
    el("details", { style: "margin:4px 0 10px;border:1px solid var(--border);border-radius:8px;padding:8px 12px" },
      el("summary", { style: "cursor:pointer;color:var(--muted)" }, "تنظیمات پیشرفته (تیونینگ TCP/SSH)"),
      el("div", { class: "row", style: "margin-top:12px" },
        el("div", { class: "field" }, el("label", {}, "بافر کپی (KB، پیش‌فرض ۳۲)"), inp("buffer_size", t.buffer_size || "", { type: "number", min: 0, max: 8192, placeholder: "32" })),
        el("div", { class: "field" }, el("label", {}, "بافر سوکت SO_SNDBUF/RCVBUF (KB)"), inp("socket_buffer", t.socket_buffer || "", { type: "number", min: 0, max: 65536, placeholder: "پیش‌فرض سیستم" }))),
      el("div", { class: "row" },
        el("div", { class: "field" }, el("label", {}, "MSS (بایت، ۰ = پیش‌فرض)"), inp("mss", t.mss || "", { type: "number", min: 0, max: 9000, placeholder: "0" })),
        checkbox("disable_nodelay", "غیرفعال‌کردن TCP_NODELAY (فعال‌کردن Nagle)", t.disable_nodelay)),
      el("p", { class: "muted", style: "margin:2px 0 0;font-size:12px" }, "این تنظیمات روی پای کلاینت↔سرور و ترانسپورت SSH↔خارج اعمال می‌شوند. MTU روی تانل TCP معنا ندارد؛ MSS نزدیک‌ترین معادل است.")),
    el("div", { class: "row" },
      checkbox("compression", "فشرده‌سازی", t.compression),
      checkbox("enabled", "فعال‌سازی و اجرا پس از ذخیره", t.enabled !== false)),
    el("hr"),
    el("div", { style: "display:flex;gap:8px;justify-content:flex-end" },
      el("button", { class: "ghost", onclick: () => overlay.remove() }, "انصراف"),
      el("button", { id: "saveBtn", onclick: save }, "ذخیره"))));
  document.body.append(overlay);
  syncAuth();
}

// ---------- tunnel detail (logs + chart) ----------
function openDetail(apiBase, id) {
  const overlay = el("div", { class: "overlay", onclick: (e) => { if (e.target === overlay) close(); } });
  const body = el("div", {}, el("div", { class: "muted" }, "در حال بارگذاری…"));
  overlay.append(el("div", { class: "modal", style: "width:760px" }, body));
  document.body.append(overlay);
  let timer = null;
  const close = () => { if (timer) clearInterval(timer); overlay.remove(); };
  const hist = { in: [], out: [] };
  const draw = (canvas) => {
    const ctx = canvas.getContext("2d");
    const w = canvas.width = canvas.clientWidth, h = canvas.height = 120;
    ctx.clearRect(0, 0, w, h);
    const max = Math.max(1, ...hist.in, ...hist.out);
    const line = (arr, color) => {
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
      arr.forEach((v, i) => { const x = (i / Math.max(1, arr.length - 1)) * w, y = h - (v / max) * (h - 8) - 4; i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
      ctx.stroke();
    };
    line(hist.in, "#3fb950"); line(hist.out, "#3b82f6");
  };
  const tick = async () => {
    let t, logs = "";
    try { t = await req(apiBase, "GET", "/tunnels/" + id); }
    catch (e) { body.innerHTML = ""; body.append(el("div", { class: "err" }, e.message)); return; }
    try { logs = (await req(apiBase, "GET", `/tunnels/${id}/logs`)).logs; } catch (_) {}
    const st = t.status && t.status.stat, r = tunnelRate("detail" + id, t);
    hist.in.push(r.ri); hist.out.push(r.ro);
    if (hist.in.length > 60) { hist.in.shift(); hist.out.shift(); }
    body.innerHTML = "";
    body.append(
      el("div", { style: "display:flex;justify-content:space-between;align-items:center" }, el("h3", { style: "margin:0" }, t.name + " "), statusBadge(t)),
      el("div", { class: "muted", style: "margin:4px 0 14px;direction:ltr;text-align:right" }, `${t.username}@${t.remote_host}:${t.remote_port}`),
      el("label", {}, "نمودار ترافیک — 🟢 ورودی(دانلود) 🔵 خروجی(آپلود)"),
      (() => { const c = el("canvas"); setTimeout(() => draw(c), 0); return c; })(),
      el("div", { class: "stats", style: "margin:14px 0" },
        stat("ورودی", fmtRate(r.ri)), stat("خروجی", fmtRate(r.ro)),
        stat("مجموع ورودی", fmtBytes(st ? st.bytes_in : 0)), stat("مجموع خروجی", fmtBytes(st ? st.bytes_out : 0)),
        stat("اتصالات فعال", st ? st.active_conns : 0), stat("ورکرها", st ? `${st.connected_workers}/${st.total_workers}` : "-")),
      st && st.last_error ? el("div", { class: "err" }, "آخرین خطا: " + st.last_error) : null,
      el("hr"), el("label", {}, "لاگ سرویس (journalctl)"), el("pre", { class: "logs" }, logs || "بدون لاگ"),
      el("div", { style: "display:flex;justify-content:flex-end;margin-top:14px" }, el("button", { class: "ghost", onclick: close }, "بستن")));
  };
  tick(); timer = setInterval(tick, 2000);
}

// ---------- settings ----------
async function viewSettings(m) {
  let s;
  try { s = await api("GET", "/settings"); } catch (e) { m.append(el("div", { class: "err" }, e.message)); return; }
  const listen = el("input", { value: s.listen });
  const path = el("input", { value: s.base_path, placeholder: "خالی = بدون مسیر" });
  const user = el("input", { value: s.username });
  const pass = el("input", { type: "password", placeholder: "خالی = بدون تغییر" });
  const master = el("input", { type: "checkbox", style: "width:auto" }); master.checked = !!s.master_enabled;
  const save = async () => {
    try {
      await api("PUT", "/settings", {
        listen: listen.value.trim(), base_path: path.value.trim(),
        username: user.value.trim(), new_password: pass.value, master_enabled: master.checked,
      });
      toast("ذخیره شد — برای اعمال کامل، سرویس را ری‌استارت کنید");
      SESSION.master_enabled = master.checked;
    } catch (e) { toast(e.message, true); }
  };
  m.append(
    el("h2", {}, "تنظیمات"),
    el("div", { class: "card", style: "margin-top:14px;max-width:560px" },
      el("h3", { style: "margin-top:0" }, "نقش این سرور"),
      el("div", { class: "field", style: "display:flex;align-items:center;gap:8px" }, master, el("label", { style: "margin:0" }, "این سرور، سرور مرکزی (Master) است — نمایش داشبورد نودها")),
      el("div", { class: "field" }, el("label", {}, "توکن این نود (برای ثبت در سرور مرکزی)"),
        el("input", { value: s.node_token, readonly: "1", style: "direction:ltr;text-align:left", onclick: (e) => e.target.select() })),
      el("hr"),
      el("h3", {}, "دسترسی پنل"),
      el("div", { class: "field" }, el("label", {}, "آدرس و پورت پنل (listen)"), listen),
      el("div", { class: "field" }, el("label", {}, "مسیر وب (web path)"), path),
      el("div", { class: "field" }, el("label", {}, "نام کاربری مدیر"), user),
      el("div", { class: "field" }, el("label", {}, "رمز عبور جدید"), pass),
      el("button", { onclick: save }, "ذخیره تنظیمات"),
      el("p", { class: "muted", style: "margin-top:12px" }, "تغییر پورت/مسیر وب یا فعال‌سازی Master نیازمند ‎systemctl restart sshtunnel-panel‎ است.")));
}

boot();
