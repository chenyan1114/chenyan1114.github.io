/* Card 6: DPP engine demo. DOM wiring only; DppEngine (dpp-engine.js) does the work, VcEngine signs and verifies.
   Uses the page's issuer key (card 2) and, optionally, the signed VC in card 3 as the linked ISO certificate. */
"use strict";

const dpp = { mapped: null, bundle: null, cert: null };

for (const [key, a] of Object.entries(DppEngine.adapters)) $("dppAdapter").append(new Option(a.name, key));
for (const c of Object.keys(DppEngine.categories)) $("dppCategory").append(new Option(c, c));
for (const [key, name] of Object.entries(DppEngine.policy.names)) $("dppRole").append(new Option(name, key));

function loadDppSample() {
  const adapter = $("dppAdapter").value;
  $("dppInput").value = adapter === "csv" ? DppEngine.samples.csv
    : adapter === "sap" ? DppEngine.samples.sap
    : JSON.stringify({ gtin: "4712345000039", serial: "TX-0001", name: "有機棉 T 恤", category: "紡織品", fibre: "有機棉 95%、彈性纖維 5%",
      carbon: 6.2, care: "30°C 洗、勿烘乾", svhc: "無（< 0.1% w/w）", origin: "印度（紡紗）、台灣（織造、裁縫）" }, null, 2);
  $("dppMapping").value = "";
}
$("dppAdapter").addEventListener("change", loadDppSample);
on("btnDppSample", loadDppSample);
loadDppSample();

function renderDppFields(m) {
  const t = document.createElement("table");
  t.className = "dppTable";
  t.innerHTML = "<thead><tr><th>欄位</th><th>值</th><th>分級</th></tr></thead>";
  const body = t.createTBody();
  const p = m.product;
  for (const [label, v] of [["GTIN", p.gtin], ["序號", p.serial], ["品名", p.name], ["類別", p.category], ["製造場址", p.facility], ["製造日期", p.madeOn]]) {
    if (!v) continue;
    const row = body.insertRow();
    row.insertCell().textContent = label;
    row.insertCell().textContent = v;
    row.insertCell().append(Object.assign(document.createElement("span"), { className: "tier", textContent: "識別" }));
  }
  for (const a of m.attributes) {
    const row = body.insertRow();
    row.insertCell().textContent = a.label;
    row.insertCell().textContent = a.value ? `${a.value}${a.unit ? " " + a.unit : ""}` : "（缺）";
    row.insertCell().append(Object.assign(document.createElement("span"), { className: `tier ${a.tier}`, textContent: DppEngine.tiers[a.tier] }));
  }
  $("dppFields").replaceChildren(t);
}

on("btnDppMap", () => {
  try {
    const mapping = $("dppMapping").value.trim() ? JSON.parse($("dppMapping").value) : undefined;
    dpp.mapped = DppEngine.fromErp({ adapter: $("dppAdapter").value, input: $("dppInput").value, mapping, category: $("dppCategory").value });
    renderDppFields(dpp.mapped);
    const notes = [];
    if (dpp.mapped.missing.length) notes.push(`⚠ 缺少必填欄位：${dpp.mapped.missing.join("、")}`);
    if (dpp.mapped.unmapped.length) notes.push(`ℹ 沒有對應到 DPP 的來源欄位：${dpp.mapped.unmapped.join("、")}`);
    if (!dpp.mapped.product.gtin || !dpp.mapped.product.serial) notes.push("✗ 缺少 GTIN 或序號，無法組成 GS1 路徑");
    showStatus("dppMsg", notes.some((n) => n.startsWith("✗")) ? "err" : dpp.mapped.missing.length ? "warn" : "ok",
      notes.length ? notes.join("　") : `✓ 已轉換：${dpp.mapped.product.category}，${dpp.mapped.attributes.length} 個護照欄位`);
  } catch (e) {
    dpp.mapped = null;
    $("dppFields").replaceChildren();
    showStatus("dppMsg", "err", "轉換失敗：" + e.message);
  }
});

/* The signed VC in card 3, if any, to link as the product's certificate */
function card3Cert() {
  try {
    const vc = JSON.parse($("vcOut").textContent);
    return isPlainObject(vc) && vc.proof ? vc : null;
  } catch {
    return null;
  }
}

on("btnDppIssue", async () => {
  if (!dpp.mapped) return showStatus("dppMsg", "err", "請先按 ① 轉換成 DPP。");
  if (!issuerKeys) return showStatus("dppMsg", "err", "請先在第 2 卡產生發證者（issuer）DID。");
  dpp.cert = $("dppLinkCert").checked ? card3Cert() : null;
  try {
    showStatus("dppMsg", "", "簽發中…");
    const { product, attributes } = dpp.mapped;
    const bundle = await DppEngine.buildPassport({
      product: { ...product, manufacturer: { id: issuerKeys.did, ...($("inHolderName").value.trim() && { name: $("inHolderName").value.trim() }) } },
      attributes,
      issuer: issuerKeys.did,
      certificates: dpp.cert ? [dpp.cert] : [],
      resolverHost: "id.example.com",
      status: () => VcEngine.statusFor(issuerKeys, { ledger: $("ledgerMode").value, blockNumber: currentBlock }),
    });
    dpp.bundle = await DppEngine.signPassport(bundle, (doc) => VcEngine.sign(doc, issuerKeys));
    $("dppVc").textContent = JSON.stringify({ passport: dpp.bundle.passport, sections: dpp.bundle.sections }, null, 2);
    $("dppOut").hidden = false;
    $("dppResolver").hidden = false;
    $("dppPath").textContent = `GS1 路徑（資料庫的 key）：${dpp.bundle.upi}`;
    const n = Object.keys(dpp.bundle.sections).length;
    showStatus("dppMsg", "ok", `✓ 已簽發：公開護照 1 張＋分級欄位 ${n} 張（${dpp.bundle.passport.proof.cryptosuite}）` +
      (dpp.cert ? "，並引用第 3 卡的證書。" : "。"));
  } catch (e) {
    showStatus("dppMsg", "err", "簽發失敗：" + e.message);
  }
});

on("btnDppResolve", () => {
  if (!dpp.bundle) return;
  const res = DppEngine.resolve(dpp.bundle, { role: $("dppRole").value, accept: $("dppAccept").value });
  $("dppResolveMeta").textContent = `HTTP ${res.status}　Content-Type: ${res.contentType}　可讀分級：${res.tiers.map((t) => DppEngine.tiers[t]).join("、")}`;
  const html = res.contentType === "text/html";
  $("dppHtml").hidden = !html;
  $("dppJson").hidden = html;
  if (html) $("dppHtml").srcdoc = res.body;
  else $("dppJson").textContent = JSON.stringify(res.body, null, 2);
});

on("btnDppVerify", async () => {
  if (!dpp.bundle) return;
  $("dppVerify").textContent = "驗證中…";
  const certificates = dpp.cert ? { [dpp.cert.id]: dpp.cert } : {};
  const r = await DppEngine.verifyPassport(dpp.bundle.passport, {
    certificates, verify: (vc) => VcEngine.verify(vc, { rpcUrl: $("inRpc").value.trim() || undefined }),
  });
  for (const l of r.linked) (l.ok ? r.passes : r.warns).push(`[引用證書] ${l.reason}（${l.id}）`);
  renderReport(r, $("dppVerify"));
});
