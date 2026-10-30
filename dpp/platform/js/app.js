/* App shell: hash router, role-based navigation, event delegation, toasts, boot. */
"use strict";

const $id = (id) => document.getElementById(id);

const NAV = {
  brand: [["#/home", "總覽"], ["#/products", "產品與護照"], ["#/certificates", "持有證書"], ["#/repairers", "授權維修商"], ["#/keys", "金鑰與 DID"], ["#/audit", "稽核紀錄"]],
  cb: [["#/home", "總覽"], ["#/issued", "證書管理"], ["#/issue", "簽發證書"], ["#/status", "狀態清單"], ["#/keys", "金鑰與 DID"], ["#/audit", "稽核紀錄"]],
  repairer: [["#/access", "查詢維修資訊"], ["#/wallet", "錢包"], ["#/keys", "金鑰與 DID"], ["#/audit", "稽核紀錄"]],
  root: [["#/trust", "信任註冊處"], ["#/tenants", "租戶"], ["#/registry", "EU DPP 註冊處"], ["#/hosting", "託管檔案"], ["#/ledger", "稽核帳本"]],
};
const PUBLIC_NAV = [["#/scan", "公開掃碼頁"], ["#/verify", "驗證工具"]];
const SWITCH_ORGS = ["fantech", "tqv", "repair", "platform"];

// [pattern, page, kinds allowed (null = everyone), options]
const ROUTES = [
  [/^#\/01\/(?<gtin>\d{14})\/21\/(?<serial>[^/]+)$/, pagePublic, null, { bare: true }],
  [/^#\/scan$/, pageScanList, null],
  [/^#\/verify$/, pageVerifyTool, null],
  [/^#\/home$/, () => (me().kind === "cb" ? pageCbHome() : pageBrandHome()), ["brand", "cb"]],
  [/^#\/products$/, pageProducts, ["brand"]],
  [/^#\/products\/new$/, pageProductNew, ["brand"]],
  [/^#\/passport\/(?<id>[\w-]+)$/, pagePassport, ["brand"]],
  [/^#\/certificates$/, pageHeldCerts, ["brand"]],
  [/^#\/repairers$/, pageRepairers, ["brand"]],
  [/^#\/issued$/, pageIssued, ["cb"]],
  [/^#\/issue$/, pageIssue, ["cb"]],
  [/^#\/status$/, pageStatus, ["cb", "brand"]],
  [/^#\/access$/, pageAccess, ["repairer"]],
  [/^#\/wallet$/, pageWallet, ["repairer"]],
  [/^#\/keys$/, pageKeys, ["brand", "cb", "repairer", "root"]],
  [/^#\/audit$/, () => pageAudit(), ["brand", "cb", "repairer"]],
  [/^#\/trust$/, pageTrust, ["root"]],
  [/^#\/tenants$/, pageTenants, ["root"]],
  [/^#\/registry$/, pageRegistry, ["root"]],
  [/^#\/hosting$/, pageHosting, ["root"]],
  [/^#\/ledger$/, pageLedger, ["root"]],
];
// Actions that only change the DOM in place; re-rendering would throw away unsaved edits
const LOCAL_ACTIONS = new Set(["addAttr", "delAttr", "vtSample"]);

const go = (hash) => { if (location.hash === hash) render(); else location.hash = hash; };
const homeOf = (org) => NAV[org.kind][0][0];

function renderShell(current) {
  const org = me();
  $id("orgSwitch").innerHTML = SWITCH_ORGS.map((id) => {
    const o = Store.state.orgs[id];
    return `<option value="${id}" ${id === org.id ? "selected" : ""}>${escHtml(o.name)}（${KIND_NAMES[o.kind]}）</option>`;
  }).join("");
  const link = ([href, label]) => `<li><a href="${href}" ${current.startsWith(href) ? 'aria-current="page"' : ""}>${label}</a></li>`;
  $id("nav").innerHTML = `<ul>${NAV[org.kind].map(link).join("")}</ul><p class="nav-label">公開頁面</p><ul>${PUBLIC_NAV.map(link).join("")}</ul>`;
  $id("orgDid").textContent = org.did;
}

let renderSeq = 0;
async function render() {
  const seq = ++renderSeq;
  const hash = location.hash || homeOf(me());
  let match = null;
  for (const [re, page, kinds, opts = {}] of ROUTES) {
    const m = re.exec(hash);
    if (m) { match = { page, kinds, opts, params: m.groups ?? {} }; break; }
  }
  if (!match) return go(homeOf(me()));
  if (match.kinds && !match.kinds.includes(me().kind)) return go(homeOf(me()));
  if (UI.tamper && match.page !== pageLedger) ACTIONS.untamper(); // the tamper demo never outlives its page
  document.body.classList.toggle("bare", !!match.opts.bare);
  renderShell(hash);
  const view = $id("view");
  try {
    const out = await match.page(match.params);
    if (seq !== renderSeq) return; // a newer navigation won
    view.innerHTML = out.s;
    await hydrateVerify(view);
  } catch (e) {
    console.error(e);
    view.innerHTML = html`<div class="alert bad">這一頁載入失敗：${e.message}</div>`.s;
  }
}

let toastTimer;
function toast(msg, kind = "ok") {
  const t = $id("toast");
  t.textContent = msg;
  t.className = "show " + kind;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = ""), 3200);
}

async function runHandler(fn, el, after) {
  el?.setAttribute("aria-busy", "true");
  try {
    await fn();
    if (after) await render();
  } catch (e) {
    console.error(e);
    toast(e.message, "bad");
  } finally {
    el?.removeAttribute("aria-busy");
  }
}

function wireEvents() {
  document.addEventListener("click", (ev) => {
    const as = ev.target.closest("[data-as]");
    if (as) { Store.state.ui.org = as.dataset.as; UI.access = null; Store.save(); }
    const el = ev.target.closest("[data-act]");
    if (!el || el.disabled || !ACTIONS[el.dataset.act]) return;
    ev.preventDefault();
    if (el.dataset.confirm && el.dataset.armed !== "1") {
      el.dataset.armed = "1";
      el.dataset.label = el.textContent;
      el.textContent = el.dataset.confirm;
      setTimeout(() => { if (el.isConnected) { el.dataset.armed = ""; el.textContent = el.dataset.label; } }, 4000);
      return;
    }
    runHandler(() => ACTIONS[el.dataset.act](el, ev), el, !LOCAL_ACTIONS.has(el.dataset.act));
  });
  document.addEventListener("change", (ev) => {
    const el = ev.target.closest("[data-act-change]");
    if (el && ACTIONS[el.dataset.actChange]) runHandler(() => ACTIONS[el.dataset.actChange](el, ev), el, !LOCAL_ACTIONS.has(el.dataset.actChange));
  });
  document.addEventListener("submit", (ev) => {
    const f = ev.target.closest("[data-form]");
    if (!f || !FORMS[f.dataset.form]) return;
    ev.preventDefault();
    const data = Object.fromEntries(new FormData(f));
    runHandler(() => FORMS[f.dataset.form](f, data), f.querySelector("button:not([type=button])"), false);
  });
  $id("orgSwitch").addEventListener("change", (ev) => {
    Store.state.ui.org = ev.target.value;
    UI.access = null;
    Store.save();
    go(homeOf(me()));
  });
  $id("btnReset").addEventListener("click", async (ev) => {
    const b = ev.currentTarget;
    if (b.dataset.armed !== "1") {
      b.dataset.armed = "1";
      b.textContent = "確定重設？所有資料會重建";
      setTimeout(() => { b.dataset.armed = ""; b.textContent = "重設示範資料"; }, 4000);
      return;
    }
    Store.reset();
    KMS.handles.clear();
    Hosting.files.clear();
    UI.access = null;
    UI.tamper = null;
    await boot();
  });
  $id("menuToggle").addEventListener("click", () => document.body.classList.toggle("nav-open"));
  $id("nav").addEventListener("click", (ev) => { if (ev.target.closest("a")) document.body.classList.remove("nav-open"); });
  window.addEventListener("hashchange", render);
}

async function boot() {
  $id("view").innerHTML = '<div class="booting"><p class="loading" id="bootMsg">載入平台資料…</p></div>';
  try {
    await bootPlatform((msg) => { const m = $id("bootMsg"); if (m) m.textContent = msg + "…"; });
  } catch (e) {
    console.error(e);
    $id("view").innerHTML = html`<div class="alert bad">平台無法啟動：${e.message}。這個頁面需要支援 Ed25519 的瀏覽器（Chrome 137+、Firefox 129+、Safari 17+）。</div>`.s;
    return;
  }
  await render();
}

wireEvents();
boot();
