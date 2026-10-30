/* Pages of the platform frontend. Each page is an async function returning HTML; buttons and forms name their
   handler with data-act / data-form, and app.js dispatches to ACTIONS / FORMS. All data goes through services.js. */
"use strict";

/* ---------- Tiny templating: html`` escapes every value except Raw ---------- */
class Raw { constructor(s) { this.s = s; } toString() { return this.s; } }
const raw = (s) => new Raw(s);
const escHtml = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
const fmtVal = (v) => (v == null || v === false ? "" : v instanceof Raw ? v.s : Array.isArray(v) ? v.map(fmtVal).join("") : escHtml(v));
const html = (strings, ...vals) => raw(strings.reduce((out, s, i) => out + s + (i < vals.length ? fmtVal(vals[i]) : ""), ""));

const ACTIONS = {}; // data-act="name" → async (el, ev)
const FORMS = {};   // data-form="name" → async (form, data)
const UI = { access: null, tamper: null, verifyInput: "" }; // per-session page state

const me = () => Store.org(Store.state.ui.org);
const dateFmt = (iso) => (iso ? new Date(iso).toLocaleString("zh-TW", { hour12: false, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" }) : "—");
const dayFmt = (iso) => (iso ? String(iso).slice(0, 10) : "—");
const orgName = (did) => Store.orgByDid(did)?.name ?? did;
const localUrl = (hash) => location.href.split("#")[0] + hash;
const publicHash = (item) => `#/01/${item.gtin}/21/${encodeURIComponent(item.serial)}`;

const CHIPS = {
  active: ["有效", "ok"], suspended: ["已暫停", "warn"], revoked: ["已撤銷", "bad"],
  draft: ["草稿", "muted"], published: ["已發布", "ok"], retired: ["已退役", "muted"],
  valid: ["可信", "ok"], warning: ["需注意", "warn"], invalid: ["不可信", "bad"],
  pass: ["通過", "ok"], warn: ["注意", "warn"], fail: ["失敗", "bad"],
};
const chip = (key, text) => html`<span class="chip ${CHIPS[key]?.[1] ?? "muted"}">${text ?? CHIPS[key]?.[0] ?? key}</span>`;
const tierChip = (t) => html`<span class="chip tier-${t}">${TIERS[t]}</span>`;

const pageHead = (title, sub, actions = "") => html`
  <div class="page-head"><div><h1>${title}</h1>${sub ? html`<p class="sub">${sub}</p>` : ""}</div><div class="actions">${actions}</div></div>`;
const stat = (label, value, note) => html`<div class="stat"><span class="stat-l">${label}</span><span class="stat-v">${value}</span>${note ? html`<span class="stat-n">${note}</span>` : ""}</div>`;
const empty = (text) => html`<div class="empty">${text}</div>`;
const jsonBlock = (obj, summary = "查看 JSON") => html`<details class="json"><summary>${summary}</summary><pre>${JSON.stringify(obj, null, 2)}</pre></details>`;
const kv = (pairs) => html`<dl class="kv">${pairs.filter(Boolean).map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>`;
const mono = (s) => html`<code class="mono">${s}</code>`;
// Two-step button for irreversible actions: the first click arms it, the second one runs it
const dangerBtn = (act, label, confirm, data = {}) =>
  html`<button type="button" class="btn danger sm" data-act="${act}" data-confirm="${confirm}" ${raw(Object.entries(data).map(([k, v]) => `data-${k}="${escHtml(v)}"`).join(" "))}>${label}</button>`;

function qrSvg(text) {
  if (typeof qrcode === "undefined") return html`<p class="muted">QR 函式庫沒有載入。</p>`;
  for (const level of ["M", "L"]) {
    try {
      const qr = qrcode(0, level);
      qr.addData(text, "Byte");
      qr.make();
      return raw(qr.createSvgTag({ cellSize: 4, margin: 2, scalable: true }));
    } catch {}
  }
  return html`<p class="muted">內容太長，無法產生 QR code。</p>`;
}

/* Verification result: verdict line plus the four questions; placeholders are filled by hydrateVerify() */
const VERDICT_TEXT = {
  valid: ["✓", "可信", "簽章正確、發證者在信任鏈上、沒有被撤銷，也在有效期內。"],
  warning: ["⚠", "需注意", "憑證本身有效，但有項目需要留意（見下方）。"],
  invalid: ["✗", "不可信", "至少一項檢查沒有通過，請不要依賴這份資料。"],
};
function verdictView(res, { compact = false } = {}) {
  const [icon, title, note] = VERDICT_TEXT[res.verdict];
  return html`
    <div class="verdict v-${res.verdict}${compact ? " compact" : ""}">
      <div class="verdict-head"><span class="verdict-icon" aria-hidden="true">${icon}</span><div><strong>${title}</strong><p>${note}</p></div></div>
      <ol class="checks">${res.checks.map((c) => html`
        <li class="c-${c.status}"><span class="c-icon" aria-hidden="true">${{ pass: "✓", warn: "⚠", fail: "✗" }[c.status]}</span>
          <div><b>${c.label}</b><span>${c.detail}</span></div></li>`)}</ol>
      ${res.linked?.length ? html`<div class="linked"><b>引用的證書</b>${res.linked.map((l) => html`
        <div class="linked-row">${l.cert ? html`<span>${l.cert.credentialSubject.certificationStandard} · ${l.cert.credentialSubject.certificateNumber}</span>
          ${l.digestOk ? chip(l.result.verdict, l.result.verdict === "valid" ? "有效" : l.result.checks.find((c) => c.status !== "pass")?.detail) : chip("fail", "雜湊不符，證書被換過")}`
          : html`<span>${l.rel.id}</span>${chip("fail", "找不到這張證書")}`}</div>`)}</div>` : ""}
      ${compact ? "" : html`<details class="lines"><summary>完整檢查紀錄</summary><ul>${res.checks.flatMap((c) => c.lines ?? [c.detail]).map((t) => html`<li>${t}</li>`)}</ul></details>`}
    </div>`;
}
const verifySlot = (vcId, compact) => html`<div class="verify-slot" data-verify="${vcId}"${compact ? raw(' data-compact="1"') : ""}><div class="loading">驗證中…</div></div>`;

async function hydrateVerify(root) {
  for (const el of root.querySelectorAll("[data-verify]")) {
    const vc = Store.state.credentials[el.dataset.verify]?.vc;
    try {
      el.innerHTML = vc ? verdictView(await Verify.credential(vc), { compact: !!el.dataset.compact }).s : empty("找不到這份憑證").s;
    } catch (e) {
      el.innerHTML = html`<p class="err">驗證時發生錯誤：${e.message}</p>`.s;
    }
  }
}

/* ---------- Shared pages ---------- */
async function pageKeys() {
  const org = me(), keys = KMS.keysOf(org.id), doc = DidService.document(org);
  return html`
    ${pageHead("金鑰與 DID", "私鑰保存在 KMS，簽章服務只拿到不可匯出的金鑰控制代碼。DID 文件由平台代管發布。",
      html`<button class="btn primary" data-act="rotate">輪替金鑰</button>`)}
    <section class="card">
      ${kv([["DID", mono(org.did)], ["DID 文件位置", mono(DidService.url(org))], ["簽章演算法", "Ed25519（eddsa-jcs-2022）"]])}
    </section>
    <section class="card">
      <h2>金鑰</h2>
      <div class="table-wrap"><table class="data"><thead><tr><th>金鑰</th><th>狀態</th><th>建立時間</th><th>公鑰</th><th></th></tr></thead><tbody>
      ${keys.map((k) => html`<tr><td>${mono("#" + fragmentOf(k.id))}</td><td>${chip(k.state === "active" ? "active" : k.state, k.state === "active" ? "使用中" : undefined)}</td>
        <td>${dateFmt(k.createdAt)}</td><td>${mono(k.publicKeyMultibase.slice(0, 18) + "…")}</td>
        <td class="right">${k.state !== "revoked" ? dangerBtn("revokeKey", "撤銷", "確定撤銷？它簽過的憑證會全部失效", { key: k.id }) : ""}</td></tr>`)}
      </tbody></table></div>
      <p class="note">輪替後，舊金鑰改為「已退役」但仍列在 DID 文件裡，所以它簽過的憑證繼續可以驗證。撤銷則會把金鑰從 DID 文件移除，用在金鑰外洩的時候。</p>
    </section>
    <section class="card"><h2>目前發布的 did.json</h2><pre class="code">${JSON.stringify(doc, null, 2)}</pre></section>`;
}
ACTIONS.rotate = async () => { const k = await DidService.rotate(me().id); toast(`已啟用 #${fragmentOf(k.id)}`); };
ACTIONS.revokeKey = async (el) => { await DidService.revoke(el.dataset.key); toast("金鑰已撤銷並自 DID 文件移除"); };

async function pageAudit({ all = false } = {}) {
  const org = me();
  const rows = Store.state.audit.filter((e) => all || e.actor === org.id).slice().reverse();
  return html`
    ${all ? "" : pageHead("稽核紀錄", "這個組織的所有寫入動作。完整帳本在平台營運的「稽核帳本」。")}
    <div class="table-wrap card flush"><table class="data"><thead><tr><th>#</th><th>時間</th>${all ? html`<th>執行者</th>` : ""}<th>動作</th><th>對象</th><th>雜湊</th></tr></thead><tbody>
    ${rows.map((e) => html`<tr${UI.tamper?.seq === e.seq ? raw(' class="tampered"') : ""}><td class="num">${e.seq}</td><td>${dateFmt(e.at)}</td>${all ? html`<td>${Store.state.orgs[e.actor]?.name ?? e.actor}</td>` : ""}
      <td>${e.action}</td><td class="wrap">${e.target}</td><td>${mono(e.hash.slice(0, 10) + "…")}</td></tr>`)}
    </tbody></table></div>`;
}

/* ---------- Brand (economic operator) ---------- */
async function pageBrandHome() {
  const org = me();
  const items = Catalog.itemsOf(org.id);
  const published = items.filter((i) => Passports.ofItem(i.upi)?.state === "published");
  const certs = Issuance.heldBy(org.id, "iso");
  const bad = certs.filter((c) => Issuance.statusOf(c.vc) !== "active");
  const recent = Store.state.audit.filter((e) => e.actor === org.id).slice(-6).reverse();
  return html`
    ${pageHead(org.name, "品牌商主控台：建立產品、組裝並發布數位產品護照。",
      html`<a class="btn" href="#/verify">驗證工具</a><a class="btn primary" href="#/products/new">新增產品</a>`)}
    ${bad.map((c) => {
      const s = c.vc.credentialSubject, n = Passports.affectedBy(c.vc.id).length;
      return html`<div class="alert ${Issuance.statusOf(c.vc) === "revoked" ? "bad" : "warn"}"><b>${s.certificationStandard} ${s.certificateNumber} ${CHIPS[Issuance.statusOf(c.vc)][0]}。</b>
        引用它的 ${n} 本護照，消費者掃碼時會看到警告。<a href="#/certificates">查看證書</a></div>`;
    })}
    <div class="stats">
      ${stat("產品型號", Object.values(Store.state.models).filter((m) => m.orgId === org.id).length)}
      ${stat("單品", items.length)}
      ${stat("已發布護照", published.length, `${items.length - published.length} 本草稿`)}
      ${stat("持有證書", certs.length, bad.length ? `${bad.length} 張異常` : "全部有效")}
    </div>
    <div class="cols">
      <section class="card"><h2>最近發布</h2>
        ${published.length ? html`<ul class="list">${published.slice(-5).reverse().map((i) => {
          const m = Store.state.models[i.gtin], v = Passports.latest(Passports.ofItem(i.upi));
          return html`<li><a href="#/passport/${Passports.ofItem(i.upi).id}">${m.name} · ${i.serial}</a><span class="muted">v${v.version} · ${dateFmt(v.signedAt)}</span></li>`;
        })}</ul>` : empty("還沒有發布任何護照。")}
      </section>
      <section class="card"><h2>最近活動</h2>
        <ul class="list">${recent.map((e) => html`<li><span>${e.action}：${e.target}</span><span class="muted">${dateFmt(e.at)}</span></li>`)}</ul>
        <p><a href="#/audit">全部稽核紀錄</a></p>
      </section>
    </div>`;
}

async function pageProducts() {
  const org = me();
  const items = Catalog.itemsOf(org.id);
  return html`
    ${pageHead("產品與護照", "每個單品有一個唯一產品識別碼（GS1 Digital Link），護照掛在單品上。", html`<a class="btn primary" href="#/products/new">新增產品</a>`)}
    <div class="table-wrap card flush"><table class="data"><thead><tr><th>產品</th><th>序號</th><th>護照</th><th>版本</th><th>引用證書</th><th></th></tr></thead><tbody>
    ${items.map((i) => {
      const m = Store.state.models[i.gtin], p = Passports.ofItem(i.upi), v = Passports.latest(p);
      return html`<tr><td><b>${m.name}</b><br>${mono("GTIN " + i.gtin)}</td><td>${i.serial}</td><td>${chip(p.state)}</td>
        <td>${v ? "v" + v.version : "—"}</td><td>${p.draft.certIds.length || "—"}</td>
        <td class="right"><a class="btn sm" href="#/passport/${p.id}">編輯</a>${v ? html` <a class="btn sm" href="${publicHash(i)}">公開頁</a>` : ""}</td></tr>`;
    })}
    </tbody></table></div>`;
}

async function pageProductNew() {
  const org = me();
  const models = Object.values(Store.state.models).filter((m) => m.orgId === org.id);
  return html`
    ${pageHead("新增產品", "先建立型號（GTIN），再為每個實體產品建立單品（序號）。單品建立後會自動產生護照草稿。")}
    <div class="cols">
      <form class="card form" data-form="newModel"><h2>新增型號</h2>
        <label for="nm-gtin">GTIN（13 或 14 位）</label><input id="nm-gtin" name="gtin" inputmode="numeric" placeholder="例：4712345000039" required>
        <p class="hint">13 位（GTIN-13）會補成 GTIN-14；檢查碼不對會被擋下。</p>
        <label for="nm-name">產品名稱</label><input id="nm-name" name="name" placeholder="例：USB-C 充電器 GaN-65" required>
        <label for="nm-cat">ESPR 產品類別</label><select id="nm-cat" name="category">${Object.keys(CATEGORY_TEMPLATES).map((c) => html`<option>${c}</option>`)}</select>
        <button class="btn primary">建立型號</button>
      </form>
      <form class="card form" data-form="newItem"><h2>新增單品</h2>
        <label for="ni-model">型號</label><select id="ni-model" name="gtin">${models.map((m) => html`<option value="${m.gtin}">${m.name}（${m.gtin}）</option>`)}</select>
        <label for="ni-serial">序號</label><input id="ni-serial" name="serial" placeholder="例：SN-0003" required>
        <label for="ni-fac">製造場址</label><input id="ni-fac" name="facility" placeholder="例：湖口一廠">
        <label for="ni-date">製造日期</label><input id="ni-date" name="madeOn" type="date">
        <button class="btn primary">建立單品與護照草稿</button>
      </form>
    </div>`;
}
FORMS.newModel = async (f, d) => { const m = Catalog.addModel(me().id, d); Store.save(); toast(`已建立型號 ${m.name}（GTIN ${m.gtin}）`); render(); };
FORMS.newItem = async (f, d) => { const i = await Catalog.addItem(me().id, d); go(`#/passport/${Passports.ofItem(i.upi).id}`); toast("已建立單品與護照草稿"); };

async function pagePassport({ id }) {
  const p = Store.state.passports[id];
  if (!p) return empty("找不到這本護照。");
  const item = Store.state.items[p.upi], m = Store.state.models[item.gtin], v = Passports.latest(p);
  const certs = Issuance.heldBy(me().id, "iso");
  const reg = Store.state.registry[p.upi];
  return html`
    ${pageHead(`${m.name} · ${item.serial}`, html`${chip(p.state)} ${v ? `目前 v${v.version}，${dateFmt(v.signedAt)} 發布` : "尚未發布"}`,
      html`${v ? html`<a class="btn" href="${publicHash(item)}">公開頁</a>` : ""}<button class="btn primary" data-act="publish" data-id="${p.id}">${v ? "發布新版本" : "發布護照"}</button>`)}
    <div class="cols wide-left">
      <div>
        <form class="card" data-form="draft" data-id="${p.id}" id="draftForm">
          <div class="card-head"><h2>護照欄位</h2><button type="button" class="btn sm" data-act="addAttr">新增欄位</button></div>
          <p class="note">「公開」任何人掃碼都看得到；「受限」只給出示授權維修商憑證的人；「機關」只給主管機關。</p>
          <div class="table-wrap"><table class="data edit"><thead><tr><th>欄位</th><th>值</th><th>單位</th><th>存取層級</th><th></th></tr></thead>
          <tbody id="attrRows">${p.draft.attributes.map((a, i) => attrRow(a, i))}</tbody></table></div>
          <h2 class="mt">引用的證書</h2>
          ${certs.length ? html`<div class="checks-list">${certs.map((c) => {
            const s = c.vc.credentialSubject, st = Issuance.statusOf(c.vc);
            return html`<label class="check"><input type="checkbox" name="cert" value="${c.vc.id}" ${p.draft.certIds.includes(c.vc.id) ? "checked" : ""}>
              <span>${s.certificationStandard} · ${s.certificateNumber}</span>${chip(st)}</label>`;
          })}</div>` : empty("還沒有持有任何證書。")}
          <div class="form-foot"><button class="btn">儲存草稿</button><span class="muted">發布時會以目前草稿簽章；已發布的版本不會被修改。</span></div>
        </form>
      </div>
      <aside>
        <section class="card"><h2>識別碼</h2>
          ${kv([["唯一產品識別碼", mono(p.upi)], ["GTIN", mono(item.gtin)], ["序號", item.serial], ["EU 註冊識別碼", reg ? mono(reg.registrationId) : "發布時登記"], ["製造場址", item.facility || "—"], ["製造日期", item.madeOn || "—"]])}
        </section>
        ${v ? html`<section class="card qr-card"><h2>產品標籤</h2><div class="qr">${qrSvg(localUrl(publicHash(item)))}</div>
          <p class="note">正式標籤印的是 ${mono(p.upi)}。這個示範 QR 指向本頁的公開頁；資料存在這台瀏覽器裡，換一支手機掃會找不到，要等接上後端才行。</p></section>` : ""}
        <section class="card"><h2>版本</h2>
          ${p.versions.length ? html`<ol class="versions">${p.versions.slice().reverse().map((ver) => html`<li><b>v${ver.version}</b><span class="muted">${dateFmt(ver.signedAt)}</span>
            ${jsonBlock(Store.state.credentials[ver.vcId].vc, "護照 VC")}${Object.entries(ver.sections).map(([t, sid]) => jsonBlock(Store.state.credentials[sid].vc, `${TIERS[t]}欄位 VC`))}</li>`)}</ol>` : empty("發布後，每個版本都會保留在這裡。")}
        </section>
      </aside>
    </div>`;
}
const attrRow = (a, i) => html`<tr data-row>
  <td><input aria-label="欄位名稱" name="label" value="${a.label}"><input type="hidden" name="key" value="${a.key || "f" + i}"></td>
  <td><input aria-label="值" name="value" value="${a.value}"></td>
  <td class="narrow"><input aria-label="單位" name="unit" value="${a.unit ?? ""}"></td>
  <td class="narrow"><select aria-label="存取層級" name="tier">${Object.entries({ public: "公開", restricted: "受限", authority: "機關" }).map(([k, t]) => html`<option value="${k}" ${a.tier === k ? "selected" : ""}>${t}</option>`)}</select></td>
  <td class="narrow"><button type="button" class="btn ghost sm" data-act="delAttr" aria-label="刪除欄位">✕</button></td></tr>`;

function readDraft(form) {
  const attributes = [...form.querySelectorAll("[data-row]")].map((tr) => {
    const v = (n) => tr.querySelector(`[name="${n}"]`).value.trim();
    return { key: v("key"), label: v("label"), value: v("value"), unit: v("unit"), tier: v("tier") };
  }).filter((a) => a.label);
  const certIds = [...form.querySelectorAll('input[name="cert"]:checked')].map((c) => c.value);
  return { attributes, certIds };
}
ACTIONS.addAttr = () => { const tb = $id("attrRows"); tb.insertAdjacentHTML("beforeend", attrRow({ label: "", value: "", unit: "", tier: "public" }, tb.children.length).s); tb.lastElementChild.querySelector("input").focus(); };
ACTIONS.delAttr = (el) => el.closest("tr").remove();
FORMS.draft = async (f) => { Passports.saveDraft(f.dataset.id, readDraft(f)); toast("草稿已儲存"); };
ACTIONS.publish = async (el) => {
  const f = $id("draftForm");
  if (f) Passports.saveDraft(el.dataset.id, readDraft(f));
  const vc = await Passports.publish(el.dataset.id);
  toast(`已簽章並發布 v${vc.credentialSubject.passportVersion}`);
};

async function pageHeldCerts() {
  const certs = Issuance.heldBy(me().id, "iso");
  return html`
    ${pageHead("持有證書", "驗證機構簽發給本公司的 ISO 證書。狀態即時讀自驗證機構發布的狀態清單。")}
    ${certs.length ? html`<div class="grid2">${certs.map((c) => certCard(c, { holder: true }))}</div>` : empty("還沒有證書。")}`;
}
function certCard(c, { holder = false, issuer = false } = {}) {
  const s = c.vc.credentialSubject, st = Issuance.statusOf(c.vc), n = Passports.affectedBy(c.vc.id).length;
  return html`<section class="card cert">
    <div class="card-head"><div><span class="eyebrow">${s.certificationStandard}</span><h2>${s.certificateNumber}</h2></div>${chip(st)}</div>
    ${kv([["範圍", s.scope], holder ? ["驗證機構", orgName(c.vc.issuer)] : ["持有者", s.name], ["到期", dayFmt(c.vc.validUntil)], ["引用的護照", n ? `${n} 本` : "—"]])}
    ${issuer ? html`<div class="row-actions">
      ${st === "suspended" ? html`<button class="btn sm" data-act="certStatus" data-id="${c.vc.id}" data-purpose="suspension" data-on="0">恢復</button>`
        : st === "active" ? html`<button class="btn sm" data-act="certStatus" data-id="${c.vc.id}" data-purpose="suspension" data-on="1">暫停</button>` : ""}
      ${st !== "revoked" ? dangerBtn("certStatus", "撤銷", "確定撤銷？無法恢復", { id: c.vc.id, purpose: "revocation", on: "1" }) : ""}
    </div>` : ""}
    <details class="json"><summary>驗證這張證書</summary>${verifySlot(c.vc.id, true)}</details>
    ${jsonBlock(c.vc)}
  </section>`;
}

async function pageRepairers() {
  const org = me();
  const issued = Issuance.issuedBy(org.id, "repairer");
  const repairers = Object.values(Store.state.orgs).filter((o) => o.kind === "repairer");
  return html`
    ${pageHead("授權維修商", "簽發「授權維修商」憑證。維修商用錢包出示這張憑證，才能讀到護照的受限欄位。")}
    <div class="cols wide-left">
      <div class="table-wrap card flush"><table class="data"><thead><tr><th>維修商</th><th>範圍</th><th>到期</th><th>狀態</th><th></th></tr></thead><tbody>
      ${issued.map((c) => { const st = Issuance.statusOf(c.vc); return html`<tr><td>${c.vc.credentialSubject.name}<br>${mono(c.vc.credentialSubject.id)}</td><td>${c.vc.credentialSubject.scope}</td>
        <td>${dayFmt(c.vc.validUntil)}</td><td>${chip(st)}</td><td class="right">${st === "active" ? dangerBtn("certStatus", "撤銷", "確定撤銷授權？", { id: c.vc.id, purpose: "revocation", on: "1" }) : ""}</td></tr>`; })}
      </tbody></table></div>
      <form class="card form" data-form="issueRepairer"><h2>新增授權</h2>
        <label for="ir-org">維修商</label><select id="ir-org" name="org">${repairers.map((o) => html`<option value="${o.id}">${o.name}</option>`)}</select>
        <label for="ir-scope">授權範圍</label><input id="ir-scope" name="scope" value="全系列產品">
        <button class="btn primary">簽發授權憑證</button>
      </form>
    </div>`;
}
FORMS.issueRepairer = async (f, d) => { await Issuance.issueRepairer(me().id, d.org, { scope: d.scope }); toast("已簽發授權維修商憑證"); render(); };
ACTIONS.certStatus = async (el) => {
  await Issuance.setStatus(el.dataset.id, el.dataset.purpose, el.dataset.on === "1");
  toast("狀態清單已更新並重新發布");
};

/* ---------- Certification body ---------- */
async function pageCbHome() {
  const org = me();
  const certs = Issuance.issuedBy(org.id, "iso");
  const count = (s) => certs.filter((c) => Issuance.statusOf(c.vc) === s).length;
  const chain = await Trust.chain(org.did, "IsoCertificationCredential");
  return html`
    ${pageHead(org.name, "驗證機構入口：簽發、暫停與撤銷 ISO 證書。", html`<a class="btn primary" href="#/issue">簽發證書</a>`)}
    <div class="stats">${stat("已簽發", certs.length)}${stat("有效", count("active"))}${stat("暫停中", count("suspended"))}${stat("已撤銷", count("revoked"))}</div>
    <section class="card"><h2>本機構的信任鏈</h2>
      ${chain.ok ? html`<ol class="chain">${chain.steps.slice().reverse().map((s) => html`<li><b>${orgName(s.did)}</b><span>${ROLE_NAMES[s.role]}</span>${mono(s.did)}</li>`)}</ol>`
        : html`<div class="alert bad">${chain.reason}</div>`}
      <p class="note">驗證者會沿著這條鏈往上查。認可被撤銷時，本機構簽發的所有證書都會變成「不可信」。</p>
    </section>`;
}

async function pageIssued() {
  const certs = Issuance.issuedBy(me().id, "iso");
  return html`
    ${pageHead("證書管理", "暫停可以恢復；撤銷無法恢復。兩者都只是翻轉狀態清單裡的一個位元，證書本身不用重簽。", html`<a class="btn primary" href="#/issue">簽發證書</a>`)}
    ${certs.length ? html`<div class="grid2">${certs.map((c) => certCard(c, { issuer: true }))}</div>` : empty("還沒有簽發任何證書。")}`;
}

async function pageIssue() {
  const holders = Object.values(Store.state.orgs).filter((o) => o.kind === "brand");
  const next = new Date(Date.now() + 3 * 365 * 864e5).toISOString().slice(0, 10);
  return html`
    ${pageHead("簽發證書", "稽核通過後簽發 ISO 證書憑證，交付到持有者的企業錢包。")}
    <form class="card form narrow-form" data-form="issueIso">
      <label for="iso-holder">持有者</label><select id="iso-holder" name="holder">${holders.map((o) => html`<option value="${o.id}">${o.name}</option>`)}</select>
      <label for="iso-std">標準</label><select id="iso-std" name="standard">${["ISO 9001:2015", "ISO 14001:2015", "ISO 45001:2018", "ISO/IEC 27001:2022", "ISO 50001:2018"].map((s) => html`<option>${s}</option>`)}</select>
      <label for="iso-no">證書編號</label><input id="iso-no" name="number" required placeholder="例：TW-OHS-2026-0201">
      <label for="iso-scope">驗證範圍</label><input id="iso-scope" name="scope" required placeholder="例：電源產品之製造">
      <label for="iso-site">場址</label><input id="iso-site" name="site" placeholder="選填">
      <label for="iso-until">到期日</label><input id="iso-until" name="validUntil" type="date" value="${next}" required>
      <button class="btn primary">簽章並交付</button>
    </form>`;
}
FORMS.issueIso = async (f, d) => { await Issuance.issueIso(me().id, d.holder, d); toast("已簽發並交付證書"); go("#/issued"); };

async function pageStatus() {
  const lists = Object.values(Store.state.statusLists).filter((l) => l.orgId === me().id);
  return html`
    ${pageHead("狀態清單", "W3C Bitstring Status List：131,072 個位元，每張憑證隨機分到一個位置；位元為 1 代表已撤銷或暫停。")}
    <div class="grid2">${lists.map((l) => html`<section class="card">
      <div class="card-head"><h2>${{ revocation: "撤銷清單", suspension: "暫停清單" }[l.purpose]}</h2>${chip("published", "已發布")}</div>
      ${kv([["網址", mono(l.url)], ["已分配", `${l.used.length} 個位置`], ["已設為 1", `${l.set.length} 個`], ["壓縮後長度", `${l.vc?.credentialSubject.encodedList.length ?? 0} 字元（原始 16 KB）`], ["最後發布", dateFmt(l.vc?.validFrom)]])}
      ${jsonBlock(l.vc, "清單 VC")}
    </section>`)}</div>`;
}

/* ---------- Repairer: authorised access with a wallet ---------- */
async function pageAccess() {
  const items = Object.values(Store.state.items).filter((i) => Passports.ofItem(i.upi)?.state === "published");
  const A = (UI.access ??= { upi: items[0]?.upi, request: null, vp: null, result: null });
  const held = Issuance.heldBy(me().id);
  const item = Store.state.items[A.upi], model = item && Store.state.models[item.gtin];
  return html`
    ${pageHead("查詢維修資訊", "受限欄位要先證明身分：平台發出一次性請求，錢包用持有的資格憑證簽一份 VP 回應。")}
    <ol class="steps">
      <li class="step done"><div class="step-n">1</div><div class="step-b"><h3>選擇產品</h3>
        <select id="acc-item" data-act-change="accItem" aria-label="選擇產品">${items.map((i) => html`<option value="${i.upi}" ${i.upi === A.upi ? "selected" : ""}>${Store.state.models[i.gtin].name} · ${i.serial}</option>`)}</select>
        ${item ? html`<p class="muted">${mono(item.upi)}</p>` : ""}</div></li>
      <li class="step ${A.request ? "done" : "now"}"><div class="step-n">2</div><div class="step-b"><h3>平台發出出示請求</h3>
        ${A.request ? kv([["challenge（nonce）", mono(A.request.challenge)], ["domain（受眾）", mono(A.request.domain)], ["有效到", dateFmt(A.request.expiresAt)]])
          : html`<button class="btn primary" data-act="accRequest">請求受限資訊</button>`}</div></li>
      <li class="step ${A.vp ? "done" : A.request ? "now" : ""}"><div class="step-n">3</div><div class="step-b"><h3>錢包出示資格憑證</h3>
        ${held.length ? html`<div class="checks-list">${held.map((c) => html`<label class="check"><input type="checkbox" name="accVc" value="${c.vc.id}" checked>
          <span>${credType(c.vc)} · 由 ${orgName(c.vc.issuer)} 簽發</span>${chip(Issuance.statusOf(c.vc))}</label>`)}</div>` : empty("錢包裡沒有憑證。")}
        <button class="btn primary" data-act="accPresent" ${A.request && !A.vp ? "" : "disabled"}>用錢包簽署並出示</button>
        ${A.vp ? jsonBlock(A.vp, "出示的 VP") : ""}</div></li>
      <li class="step ${A.result ? (A.result.ok ? "done" : "failed") : ""}"><div class="step-n">4</div><div class="step-b"><h3>平台驗證並做授權決策</h3>
        ${A.result ? html`<ul class="decision">${A.result.steps.map((s) => html`<li class="${s.ok ? "ok" : "bad"}"><b>${s.ok ? "✓" : "✗"} ${s.label}</b><span>${s.detail}</span></li>`)}</ul>
          ${A.result.errors?.length ? html`<p class="err">錯誤類型：${A.result.errors.join("、")}</p>` : ""}
          <div class="row-actions"><button class="btn sm" data-act="accReplay">重送同一份 VP（示範重放攻擊）</button><button class="btn sm" data-act="accReset">重新開始</button></div>`
          : html`<p class="muted">出示後在這裡看到結果。</p>`}</div></li>
    </ol>
    ${A.result?.ok ? html`<section class="card"><h2>${model.name} · ${item.serial} 的受限資訊</h2>
      ${A.result.sections.length ? A.result.sections.map((s) => html`<div class="section-block"><div class="card-head"><h3>${TIERS[s.credentialSubject.tier]}欄位</h3>${tierChip(s.credentialSubject.tier)}</div>
        ${attrList(s.credentialSubject.attributes)}${verifySlot(s.id, true)}</div>`) : empty("這本護照沒有受限欄位。")}
    </section>` : ""}`;
}
const attrList = (attrs) => html`<dl class="attrs">${attrs.map((a) => html`<dt>${a.label}</dt><dd>${a.value}${a.unit ? html` <span class="unit">${a.unit}</span>` : ""}</dd>`)}</dl>`;
ACTIONS.accItem = (el) => { UI.access = { upi: el.value, request: null, vp: null, result: null }; render(); };
ACTIONS.accRequest = () => { UI.access.request = Access.request(); render(); };
ACTIONS.accPresent = async () => {
  const ids = [...document.querySelectorAll('input[name="accVc"]:checked')].map((c) => c.value);
  if (!ids.length) throw new Error("請至少選一張憑證");
  UI.access.vp = await Access.present(me().id, UI.access.request, ids);
  UI.access.result = await Access.exchange(UI.access.vp, UI.access.upi);
};
ACTIONS.accReplay = async () => { UI.access.result = await Access.exchange(UI.access.vp, UI.access.upi); };
ACTIONS.accReset = () => { UI.access = { upi: UI.access.upi, request: null, vp: null, result: null }; };

async function pageWallet() {
  const held = Issuance.heldBy(me().id);
  return html`
    ${pageHead("錢包", "本組織持有的憑證。憑證的主體是本組織的 DID，出示時用本組織的金鑰簽 VP。")}
    ${held.length ? html`<div class="grid2">${held.map((c) => html`<section class="card"><div class="card-head"><div><span class="eyebrow">${credType(c.vc)}</span><h2>${orgName(c.vc.issuer)}</h2></div>${chip(Issuance.statusOf(c.vc))}</div>
      ${kv([["主體", mono(c.vc.credentialSubject.id)], ["範圍", c.vc.credentialSubject.scope ?? "—"], ["到期", dayFmt(c.vc.validUntil)]])}
      ${verifySlot(c.vc.id, true)}${jsonBlock(c.vc)}</section>`)}</div>` : empty("錢包是空的。")}`;
}

/* ---------- Platform operator ---------- */
async function pageTrust() {
  const rows = Store.state.trust;
  return html`
    ${pageHead("信任註冊處", "平台維護的受信任發證者清單（仿 EBSI：根信任機構 → 認證機構 → 受信任發證者）。每一筆都有上一層簽的認可憑證。")}
    <div class="table-wrap card flush"><table class="data"><thead><tr><th>機構</th><th>角色</th><th>可簽發</th><th>認可者</th><th>認可狀態</th><th></th></tr></thead><tbody>
    ${rows.map((e) => {
      const acc = Store.state.credentials[e.accreditation]?.vc, st = acc ? Issuance.statusOf(acc) : null;
      return html`<tr><td><b>${orgName(e.did)}</b><br>${mono(e.did)}</td><td>${chip("muted", ROLE_NAMES[e.role])}</td>
        <td class="wrap">${e.types.map((t) => (t === "*" ? "全部" : t)).join("、")}</td><td>${e.accreditedBy ? orgName(e.accreditedBy) : "（信任錨）"}</td>
        <td>${st ? chip(st) : "—"}</td>
        <td class="right">${acc ? (st === "revoked"
          ? html`<button class="btn sm" data-act="certStatus" data-id="${acc.id}" data-purpose="revocation" data-on="0">恢復認可</button>`
          : dangerBtn("certStatus", "撤銷認可", "確定撤銷？它簽的憑證都會失去信任", { id: acc.id, purpose: "revocation", on: "1" })) : ""}</td></tr>`;
    })}
    </tbody></table></div>
    <p class="note">試試看：撤銷「台灣品質驗證」的認可，再到公開掃碼頁看護照引用的 ISO 證書變成什麼狀態。</p>`;
}

async function pageTenants() {
  return html`
    ${pageHead("租戶", "每個組織有自己的 did:web、金鑰與資料。")}
    <div class="table-wrap card flush"><table class="data"><thead><tr><th>組織</th><th>類型</th><th>DID</th><th>金鑰</th><th>統一編號</th></tr></thead><tbody>
    ${Object.values(Store.state.orgs).map((o) => html`<tr><td><b>${o.name}</b></td><td>${KIND_NAMES[o.kind]}</td><td>${mono(o.did)}</td>
      <td>${KMS.keysOf(o.id).filter((k) => k.state !== "revoked").length}</td><td>${o.vat ?? "—"}</td></tr>`)}
    </tbody></table></div>`;
}

async function pageRegistry() {
  const rows = Object.values(Store.state.registry);
  return html`
    ${pageHead("EU DPP 註冊處（模擬）", "護照第一次發布時，平台向註冊處登記唯一產品識別碼，取得註冊識別碼。")}
    <div class="table-wrap card flush"><table class="data"><thead><tr><th>註冊識別碼</th><th>唯一產品識別碼</th><th>經濟業者</th><th>登記時間</th></tr></thead><tbody>
    ${rows.map((r) => html`<tr><td>${mono(r.registrationId)}</td><td class="wrap">${mono(r.upi)}</td><td>${orgName(r.operatorDid)}</td><td>${dateFmt(r.registeredAt)}</td></tr>`)}
    </tbody></table></div>`;
}

async function pageHosting() {
  const files = [...Hosting.files.entries()].sort(([a], [b]) => a.localeCompare(b));
  return html`
    ${pageHead("託管檔案（CDN）", "驗證需要的公開檔案。任何人都能下載，驗證時不必信任平台。")}
    ${files.map(([url, doc]) => html`<section class="card file"><div class="card-head"><h2 class="mono-h">${url}</h2>${chip("muted", url.includes("/status/") || url.includes("status.") ? "狀態清單" : "DID 文件")}</div>${jsonBlock(doc, "內容")}</section>`)}`;
}

async function pageLedger() {
  const v = await Audit.verify();
  return html`
    ${pageHead("稽核帳本", "只能新增、不能修改：每一筆都包含前一筆的雜湊，改任何一筆，後面整條鏈都會對不上。",
      UI.tamper ? html`<button class="btn" data-act="untamper">還原第 ${UI.tamper.seq} 筆</button>` : html`<button class="btn" data-act="tamper">示範：偷偷改一筆</button>`)}
    <div class="alert ${v.ok ? "ok" : "bad"}">${v.ok ? `✓ 雜湊鏈完整，共 ${v.count} 筆。` : `✗ 雜湊鏈在第 ${v.brokenAt} 筆斷掉：這一筆被改過。`}</div>
    ${await pageAudit({ all: true })}`;
}
ACTIONS.tamper = () => {
  const e = Store.state.audit[Math.min(4, Store.state.audit.length - 1)];
  UI.tamper = { seq: e.seq, target: e.target };
  e.target += "（被改過）";
};
ACTIONS.untamper = () => {
  Store.state.audit[UI.tamper.seq - 1].target = UI.tamper.target;
  UI.tamper = null;
};

/* ---------- Public: scan list, passport page, verifier ---------- */
async function pageScanList() {
  const items = Object.values(Store.state.items).filter((i) => Passports.ofItem(i.upi)?.state === "published");
  return html`
    ${pageHead("公開掃碼頁", "模擬消費者掃產品上的 QR code。公開頁不需要登入。")}
    <div class="grid3">${items.map((i) => { const m = Store.state.models[i.gtin]; return html`<a class="card product-tile" href="${publicHash(i)}">
      <div class="qr small">${qrSvg(localUrl(publicHash(i)))}</div><div><b>${m.name}</b><span class="muted">${i.serial} · ${m.category}</span></div></a>`; })}</div>`;
}

async function pagePublic({ gtin, serial }) {
  const v = Passports.publicView(gtin, decodeURIComponent(serial));
  if (!v) return html`<div class="pub-empty"><h1>找不到這個產品</h1><p>識別碼 ${mono(`/01/${gtin}/21/${serial}`)} 沒有對應的護照。示範資料存在建立它的瀏覽器裡，用另一台裝置掃碼會找不到。</p><a class="btn" href="#/scan">回到平台</a></div>`;
  if (!v.vc) return html`<div class="pub-empty"><h1>${v.model.name}</h1><p>這個產品的護照還沒有發布。</p><a class="btn" href="#/scan">回到平台</a></div>`;
  const s = v.vc.credentialSubject, org = Store.orgByDid(v.vc.issuer);
  return html`
    <header class="pub-top"><span class="pub-brand"><img src="../img/icon.png" alt="" width="22" height="22">數位產品護照</span><a href="#/scan">回到平台</a></header>
    <article class="pub">
      <p class="eyebrow">${s.category}</p>
      <h1>${s.name}</h1>
      <p class="pub-maker">${s.manufacturer.name}</p>
      <p class="pub-ids">${mono("GTIN " + s.gtin)} ${mono("序號 " + s.serialNumber)}</p>
      ${verifySlot(v.vc.id)}
      <section class="pub-sec"><h2>產品資訊</h2>${attrList(s.attributes)}</section>
      <section class="pub-sec"><h2>識別與登記</h2>
        ${kv([["EU 註冊識別碼", mono(s.registrationId)], ["護照版本", `v${s.passportVersion}（${dateFmt(v.vc.validFrom)}）`], ["製造場址", s.facility ?? "—"], ["製造日期", s.manufacturedOn ?? "—"], ["發證者", html`${org?.name}<br>${mono(v.vc.issuer)}`]])}
      </section>
      <section class="pub-sec pub-cta"><h2>維修商或主管機關？</h2><p>拆解步驟、備品料號等受限資訊，需要用錢包出示授權憑證才能讀取。</p><a class="btn" href="#/access" data-as="repair">以授權維修商身分查詢</a></section>
      ${jsonBlock(v.vc, "原始護照憑證（JSON）")}
    </article>`;
}

async function pageVerifyTool() {
  const samples = Object.values(Store.state.credentials).filter((c) => ["passport", "iso", "repairer"].includes(c.kind));
  return html`
    ${pageHead("驗證工具", "貼上任何 W3C VC 2.0 憑證（例如 demo 首頁產生的 VC），平台會回答四個問題。")}
    <div class="cols wide-left">
      <form class="card form" data-form="verifyTool">
        <label for="vt-sample">載入平台上的憑證</label>
        <select id="vt-sample" data-act-change="vtSample"><option value="">選一張…</option>${samples.map((c) => html`<option value="${c.vc.id}">${c.kind === "passport" ? "護照" : c.kind === "iso" ? "ISO 證書" : "維修授權"}：${c.vc.credentialSubject.name ?? c.vc.credentialSubject.certificateNumber} ${c.vc.credentialSubject.serialNumber ?? c.vc.credentialSubject.certificateNumber ?? ""}</option>`)}</select>
        <label for="vt-json">憑證 JSON</label>
        <textarea id="vt-json" name="json" rows="16" spellcheck="false">${UI.verifyInput}</textarea>
        <button class="btn primary">驗證</button>
      </form>
      <div id="vt-out">${empty("結果會顯示在這裡。")}</div>
    </div>`;
}
ACTIONS.vtSample = (el) => { if (el.value) $id("vt-json").value = JSON.stringify(Store.state.credentials[el.value].vc, null, 2); };
FORMS.verifyTool = async (f, d) => {
  UI.verifyInput = d.json;
  let vc;
  try { vc = JSON.parse(d.json); } catch { throw new Error("不是合法的 JSON"); }
  $id("vt-out").innerHTML = '<div class="loading">驗證中…</div>';
  $id("vt-out").innerHTML = verdictView(await Verify.credential(vc)).s;
};

const KIND_NAMES = { root: "平台（信任根）", tao: "國家認證機構", cb: "驗證機構", brand: "品牌商", repairer: "維修商" };
