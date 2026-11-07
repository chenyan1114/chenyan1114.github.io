/* DPP engine: turns product data into Digital Product Passports and serves them per role. No DOM, no storage.
   Follows the architecture in DPP_系統架構圖.pptx:
     ERP / documents ──① strategy adapters──▶ ② field mapping table ──▶ DPP JSON keyed by the GS1 path
     Resolver: by the requester's role (Public / Partners / Government) and Accept / User-Agent, return HTML or JSON
   Passports are W3C VCs built and checked by VcEngine (vc-engine.js): a public passport credential plus one
   credential per restricted tier, linked certificates by id + digestSRI. Field tiers and required fields follow
   the ESPR idea of "information requirements per product group" (the real delegated acts are not out yet;
   the battery fields follow the Battery Regulation's passport list in spirit). */
"use strict";

const DppEngine = {
  version: "1.0",

  /* ---------- GS1 identifiers (Digital Link paths) ---------- */
  gs1: {
    // mod-10 check digit over the first 13 digits of a GTIN-14
    checkDigit(body13) {
      const sum = [...body13].reverse().reduce((s, d, i) => s + Number(d) * (i % 2 === 0 ? 3 : 1), 0);
      return String((10 - (sum % 10)) % 10);
    },
    gtin14(input) {
      let d = String(input ?? "").replace(/\D/g, "");
      if (d.length === 13) d = "0" + d; // GTIN-13 → GTIN-14 keeps the same check digit
      if (d.length !== 14) throw new Error("GTIN 應為 13 或 14 位數字");
      if (this.checkDigit(d.slice(0, 13)) !== d[13]) throw new Error(`GTIN 檢查碼錯誤（應為 ${this.checkDigit(d.slice(0, 13))}）`);
      return d;
    },
    // /01/<gtin>[/10/<batch>][/21/<serial>]: the database key of a passport
    path({ gtin, batch, serial }) {
      return `/01/${this.gtin14(gtin)}${batch ? `/10/${encodeURIComponent(batch)}` : ""}${serial ? `/21/${encodeURIComponent(serial)}` : ""}`;
    },
    link(resolverHost, ids) { return `https://${resolverHost}${this.path(ids)}`; },
    parse(pathOrUrl) {
      let p = String(pathOrUrl);
      try { p = new URL(p).pathname; } catch { /* already a path */ }
      const m = /^\/01\/(\d{14})(?:\/10\/([^/]+))?(?:\/21\/([^/]+))?\/?$/.exec(p);
      if (!m) throw new Error("不是 GS1 Digital Link 路徑（/01/<GTIN>[/10/<批號>][/21/<序號>]）");
      return { gtin: this.gtin14(m[1]), ...(m[2] && { batch: decodeURIComponent(m[2]) }), ...(m[3] && { serial: decodeURIComponent(m[3]) }) };
    },
  },

  /* ---------- passport content model ---------- */
  tiers: { public: "公開", restricted: "受限（維修、回收）", authority: "機關" },
  sections: { composition: "材料組成", environment: "環境足跡", circularity: "維修與循環", safety: "安全與有害物質", compliance: "合規文件", supplyChain: "供應鏈" },
  // Per product group: [key, label, unit, tier, section, required, example value]
  categories: {
    "電子產品": [
      ["material", "主要材料", "", "public", "composition", true, "鋁合金 62%、PC/ABS 21%、銅 9%、其他 8%"],
      ["recycled", "再生料比例", "%", "public", "composition", true, "18"],
      ["carbon", "產品碳足跡", "kg CO₂e", "public", "environment", true, "41.6"],
      ["repairability", "可修復性指數", "/ 10", "public", "circularity", true, "7.8"],
      ["warranty", "保固", "年", "public", "circularity", false, "3"],
      ["disassembly", "拆解步驟", "", "restricted", "circularity", true, "1. 移除底部 4 顆 T10 螺絲　2. 拆下風扇模組　3. 拔除主電源排線"],
      ["spareParts", "備品料號", "", "restricted", "circularity", false, "FAN-80-12V、PCB-PSU-650-R2"],
      ["hazard", "有害物質位置", "", "restricted", "safety", true, "主電容（含電解液）位於主板右側"],
      ["conformity", "符合性聲明", "", "authority", "compliance", true, "EU DoC 2026-0142（LVD、EMC、RoHS）"],
    ],
    "電池": [
      ["chemistry", "電池化學", "", "public", "composition", true, "鋰離子 NMC 811"],
      ["capacity", "額定容量", "mAh", "public", "composition", true, "10000"],
      ["carbon", "產品碳足跡", "kg CO₂e", "public", "environment", true, "12.3"],
      ["recycledCo", "再生鈷比例", "%", "public", "composition", true, "16"],
      ["cycles", "預期循環壽命", "次", "public", "circularity", false, "800"],
      ["soh", "健康狀態量測方法", "", "restricted", "circularity", true, "依 IEC 62660-1 容量測試"],
      ["dismantling", "拆解與安全", "", "restricted", "safety", true, "放電至 0% 後再拆，電芯以膠固定需加熱至 60°C"],
      ["dueDiligence", "供應鏈盡職調查報告", "", "authority", "supplyChain", true, "DD-2026-PB10K（鈷、鋰、鎳）"],
    ],
    "紡織品": [
      ["fibre", "纖維成分", "", "public", "composition", true, "有機棉 95%、彈性纖維 5%"],
      ["recycled", "再生纖維比例", "%", "public", "composition", false, "30"],
      ["carbon", "產品碳足跡", "kg CO₂e", "public", "environment", true, "6.2"],
      ["care", "洗滌與保養", "", "public", "circularity", false, "30°C 洗、勿烘乾"],
      ["svhc", "高度關注物質（SVHC）", "", "restricted", "safety", true, "無（< 0.1% w/w）"],
      ["origin", "紡紗、織造與裁縫地", "", "authority", "supplyChain", true, "印度（紡紗）、台灣（織造、裁縫）"],
    ],
  },
  fieldsOf(category) {
    const rows = this.categories[category];
    if (!rows) throw new Error(`不支援的產品類別：${category}（支援 ${Object.keys(this.categories).join("、")}）`);
    return rows.map(([key, label, unit, tier, section, required, example]) => ({ key, label, unit, tier, section, required, example }));
  },
  /* Editable attribute rows for a new passport, pre-filled with the example values (or empty) */
  template(category, { examples = true } = {}) {
    return this.fieldsOf(category).map(({ key, label, unit, tier, example }) => ({ key, label, value: examples ? example : "", unit, tier }));
  },
  /* Required fields without a value, and the rule that the public passport can't be empty */
  validate(category, attributes) {
    const byKey = Object.fromEntries(attributes.map((a) => [a.key, a]));
    const missing = this.fieldsOf(category).filter((f) => f.required && !String(byKey[f.key]?.value ?? "").trim()).map((f) => f.label);
    const problems = attributes.some((a) => a.tier === "public" && String(a.value ?? "").trim()) ? [] : ["至少要有一個公開欄位"];
    return { ok: !problems.length, missing, problems };
  },

  /* ---------- ① ERP adapters (strategy pattern) + ② field mapping table ---------- */
  // Each adapter reads one export format into a flat record; its default mapping turns source fields into DPP keys.
  // Product keys: gtin, serial, batch, name, category, facility, madeOn. Anything else maps to an attribute key.
  adapters: {
    sap: {
      name: "SAP（物料主檔＋序號欄位）",
      read: (text) => JSON.parse(text),
      mapping: { EAN11: "gtin", SERNR: "serial", CHARG: "batch", MAKTX: "name", ZZ_DPP_CATEGORY: "category", WERKS_TXT: "facility", HSDAT: "madeOn",
        ZZ_MATERIAL: "material", ZZ_RECYCLED_PCT: "recycled", ZZ_CO2E_KG: "carbon", ZZ_REPAIR_INDEX: "repairability", ZZ_WARRANTY_Y: "warranty",
        ZZ_DISASSEMBLY: "disassembly", ZZ_SPARE_PARTS: "spareParts", ZZ_HAZARD_LOC: "hazard", ZZ_DOC_REF: "conformity" },
    },
    json: {
      name: "通用 JSON（欄位名稱與 DPP 相同）",
      read: (text) => JSON.parse(text),
      mapping: {},
    },
    csv: {
      name: "CSV（第一列是欄位名稱，讀第二列）",
      read(text) {
        const rows = String(text).trim().split(/\r?\n/).map((line) => line.split(",").map((c) => c.trim().replace(/^"(.*)"$/, "$1")));
        if (rows.length < 2) throw new Error("CSV 至少要有欄位名稱列和一列資料");
        return Object.fromEntries(rows[0].map((h, i) => [h, rows[1][i] ?? ""]));
      },
      mapping: {},
    },
  },
  productKeys: ["gtin", "serial", "batch", "name", "category", "facility", "madeOn"],
  /* Read an export with one adapter and map it. mapping: source field → DPP key (overrides the adapter's default) */
  fromErp({ adapter = "json", input, mapping, category } = {}) {
    const a = this.adapters[adapter];
    if (!a) throw new Error(`不支援的轉接器：${adapter}`);
    const record = typeof input === "string" ? a.read(input) : input;
    if (!isPlainObject(record)) throw new Error("讀到的資料不是一筆紀錄（物件）");
    const table = { ...a.mapping, ...mapping };
    const product = {}, values = {}, unmapped = [];
    for (const [src, v] of Object.entries(record)) {
      const key = table[src] ?? src;
      if (this.productKeys.includes(key)) product[key] = String(v);
      else values[key] = v;
    }
    product.category ??= category;
    if (product.gtin) product.gtin = this.gs1.gtin14(product.gtin);
    const fields = this.fieldsOf(product.category);
    for (const k of Object.keys(values)) if (!fields.some((f) => f.key === k)) unmapped.push(k);
    const attributes = fields.map(({ key, label, unit, tier }) => ({ key, label, value: values[key] === undefined ? "" : String(values[key]), unit, tier }));
    return { product, attributes, unmapped, mapping: table, ...this.validate(product.category, attributes) };
  },

  /* ---------- passports as VCs ---------- */
  /* Unsigned credentials for one passport version. product: { gtin, serial, name, category, manufacturer: { id, name },
     facility?, madeOn?, upi? }; certificates: VCs to link (digestSRI); status(tier): credentialStatus for each credential */
  async buildPassport({ product, attributes, issuer, version = 1, registrationId, certificates = [], status, resolverHost } = {}) {
    const check = this.validate(product.category, attributes);
    if (!check.ok) throw new Error(check.problems.join("；"));
    const upi = product.upi ?? (resolverHost ? this.gs1.link(resolverHost, product) : this.gs1.path(product));
    const pick = (tier) => attributes.filter((a) => a.tier === tier && String(a.value ?? "").trim())
      .map(({ key, label, value, unit }) => ({ key, label, value, ...(unit && { unit }) }));
    const passport = VcEngine.credential({
      type: "DigitalProductPassportCredential",
      issuer,
      subject: {
        id: upi,
        type: "Product",
        gtin: this.gs1.gtin14(product.gtin),
        serialNumber: product.serial,
        name: product.name,
        category: product.category,
        manufacturer: product.manufacturer ?? { id: issuer },
        ...(product.facility && { facility: product.facility }),
        ...(product.madeOn && { manufacturedOn: product.madeOn }),
        ...(registrationId && { registrationId }),
        passportVersion: version,
        attributes: pick("public"),
      },
      related: await Promise.all(certificates.map((c) => VcEngine.digestSRI(c))),
      status: await status?.("public"),
    });
    // Restricted tiers are separate credentials, released only after the resolver's policy allows it
    const sections = {};
    for (const tier of ["restricted", "authority"]) {
      const attrs = pick(tier);
      if (!attrs.length) continue;
      sections[tier] = VcEngine.credential({
        type: "PassportRestrictedSection",
        issuer,
        subject: { id: upi, tier, passport: passport.id, attributes: attrs },
        status: await status?.(tier),
      });
    }
    return { upi, passport, sections };
  },
  /* sign(doc) → signed doc: VcEngine.sign with keys on the demo page, the platform's KMS signer on the platform */
  async signPassport(bundle, sign) {
    const passport = await sign(bundle.passport);
    const sections = {};
    for (const [tier, s] of Object.entries(bundle.sections)) sections[tier] = await sign(s);
    return { ...bundle, passport, sections };
  },
  /* The passport's own checks (VcEngine.verify) plus every linked certificate: found, digest matches, and verifies */
  async verifyPassport(vc, { certificates = {}, verify = (x) => VcEngine.verify(x) } = {}) {
    const report = await verify(vc);
    const linked = [];
    for (const rel of [].concat(vc.relatedResource ?? [])) {
      const cert = certificates[rel.id];
      if (!cert) { linked.push({ id: rel.id, ok: false, reason: "找不到引用的證書" }); continue; }
      if ((await VcEngine.digestSRI(cert)).digestSRI !== rel.digestSRI) { linked.push({ id: rel.id, ok: false, reason: "證書內容和護照簽下的摘要不同（被換過）" }); continue; }
      const res = await verify(cert);
      linked.push({ id: rel.id, ok: res.verdict !== "invalid", reason: res.verdict === "invalid" ? res.fails[0] : "摘要相符、證書有效", verdict: res.verdict });
    }
    return { ...report, linked, verdict: report.verdict === "invalid" ? "invalid" : linked.some((l) => !l.ok) ? "warning" : report.verdict };
  },

  /* ---------- resolver: role + Accept / User-Agent → content ---------- */
  policy: {
    names: { public: "一般大眾（Public）", partner: "合作夥伴（Partners：維修、回收）", government: "主管機關（Government）" },
    tiers: { public: ["public"], partner: ["public", "restricted"], government: ["public", "restricted", "authority"] },
    // Credential types that prove a role when presented in a VP
    roles: { AuthorizedRepairerCredential: "partner", RecyclerCredential: "partner", MarketSurveillanceAuthorityCredential: "government" },
  },
  /* The role a verified VP proves: the strongest role among its credentials that pass `accept(vc)` (trust + status) */
  async roleFromPresentation(vp, accept) {
    const rank = ["public", "partner", "government"];
    let role = "public";
    for (const vc of [].concat(vp?.verifiableCredential ?? [])) {
      const r = this.policy.roles[[].concat(vc.type).at(-1)];
      if (r && rank.indexOf(r) > rank.indexOf(role) && (await accept(vc))) role = r;
    }
    return role;
  },
  /* HTML for people (browsers), JSON for systems; Accept wins, User-Agent decides when Accept says nothing */
  negotiate(accept = "", userAgent = "") {
    for (const part of String(accept).split(",").map((s) => s.split(";")[0].trim().toLowerCase())) {
      if (part === "text/html") return "text/html";
      if (part === "application/json" || part === "application/ld+json" || part === "application/vc") return "application/json";
    }
    return /mozilla|safari|chrome/i.test(userAgent) ? "text/html" : "application/json";
  },
  /* What a role may see, grouped by section, merged from the passport and the sections it is allowed */
  view(passport, sections = {}, role = "public") {
    const tiers = this.policy.tiers[role] ?? this.policy.tiers.public;
    const s = passport.credentialSubject;
    const fields = Object.fromEntries((this.categories[s.category] ? this.fieldsOf(s.category) : []).map((f) => [f.key, f]));
    const items = [...s.attributes.map((a) => ({ ...a, tier: "public" })),
      ...tiers.filter((t) => t !== "public" && sections[t]).flatMap((t) => sections[t].credentialSubject.attributes.map((a) => ({ ...a, tier: t })))];
    const groups = {};
    for (const it of items) {
      const sec = fields[it.key]?.section ?? "other";
      (groups[sec] ??= { section: sec, label: this.sections[sec] ?? "其他", items: [] }).items.push(it);
    }
    const { attributes, ...product } = s;
    return { role, roleName: this.policy.names[role], tiers, product, issuer: passport.issuer, groups: Object.values(groups) };
  },
  /* One request to the resolver: { passport, sections } is the stored bundle for the GS1 path */
  resolve({ passport, sections = {} }, { role = "public", accept = "", userAgent = "" } = {}) {
    const tiers = this.policy.tiers[role] ?? this.policy.tiers.public;
    const contentType = this.negotiate(accept, userAgent);
    const allowed = tiers.filter((t) => t !== "public" && sections[t]).map((t) => sections[t]);
    const body = contentType === "text/html"
      ? this.renderHtml(this.view(passport, sections, role))
      : { role, tiers, passport, sections: allowed };
    return { status: 200, contentType, role, tiers, body };
  },
  renderHtml(v) {
    const esc = (x) => String(x ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
    const p = v.product;
    const groups = v.groups.map((g) => `<section><h2>${esc(g.label)}</h2><dl>${g.items.map((it) =>
      `<dt>${esc(it.label)}${it.tier !== "public" ? ` <small>（${esc(this.tiers[it.tier])}）</small>` : ""}</dt><dd>${esc(it.value)}${it.unit ? " " + esc(it.unit) : ""}</dd>`).join("")}</dl></section>`).join("");
    return `<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(p.name)}｜數位產品護照</title>
<style>body{font:15px/1.6 system-ui,sans-serif;max-width:640px;margin:0 auto;padding:16px;color:#1f2937;background:#fff}h1{font-size:1.4em;margin:.2em 0}
h2{font-size:1em;margin:1.2em 0 .3em;color:#1d4ed8}dl{display:grid;grid-template-columns:9em 1fr;gap:4px 12px;margin:0}dt{color:#6b7280}dd{margin:0}
.meta{color:#6b7280;font-size:.9em}.role{display:inline-block;background:#e0e7ff;color:#1e3a8a;border-radius:99px;padding:1px 10px;font-size:.85em}</style></head>
<body><p class="role">${esc(v.roleName)}</p><h1>${esc(p.name)}</h1>
<p class="meta">${esc(p.category)}｜GTIN ${esc(p.gtin)}｜序號 ${esc(p.serialNumber)}｜護照 v${esc(p.passportVersion)}</p>
<p class="meta">製造商：${esc(p.manufacturer?.name ?? p.manufacturer?.id)}${p.facility ? `｜${esc(p.facility)}` : ""}${p.manufacturedOn ? `｜${esc(p.manufacturedOn)}` : ""}</p>
${groups}<p class="meta">發證者 ${esc(v.issuer)}</p></body></html>`;
  },

  /* ---------- sample data for the demo page and the tests ---------- */
  samples: {
    sap: JSON.stringify({
      MATNR: "PSU-650", EAN11: "4712345000015", SERNR: "SN-0001", MAKTX: "智慧電源供應器 PSU-650", ZZ_DPP_CATEGORY: "電子產品",
      WERKS_TXT: "湖口一廠", HSDAT: "2026-09-14", ZZ_MATERIAL: "鋁合金 62%、PC/ABS 21%、銅 9%、其他 8%", ZZ_RECYCLED_PCT: 18,
      ZZ_CO2E_KG: 41.6, ZZ_REPAIR_INDEX: 7.8, ZZ_WARRANTY_Y: 3, ZZ_DISASSEMBLY: "1. 移除底部 4 顆 T10 螺絲　2. 拆下風扇模組　3. 拔除主電源排線",
      ZZ_SPARE_PARTS: "FAN-80-12V、PCB-PSU-650-R2", ZZ_HAZARD_LOC: "主電容（含電解液）位於主板右側", ZZ_DOC_REF: "EU DoC 2026-0142（LVD、EMC、RoHS）",
      ERDAT: "2026-09-01",
    }, null, 2),
    csv: "gtin,serial,name,category,chemistry,capacity,carbon,recycledCo,cycles,soh,dismantling,dueDiligence\n" +
      "4712345000022,PB-0001,行動電源 PB-10K,電池,鋰離子 NMC 811,10000,12.3,16,800,依 IEC 62660-1 容量測試,放電至 0% 後再拆,DD-2026-PB10K",
  },
};
