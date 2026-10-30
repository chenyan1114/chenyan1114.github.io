/* Mock backend of the product-grade DPP platform. Each object stands for one service in the architecture plan:
   Store (PostgreSQL), Hosting (CDN), KMS + Signer (HSM), DidService, StatusService (Bitstring Status List),
   Trust (trust registry), Issuance, Catalog, Passports, Registry (EU DPP registry), Verify, Access (OID4VP-style
   exchange + policy decision) and Audit (hash-chained ledger).
   State lives in localStorage. Files the platform publishes (did.json, status lists) are served to the official
   did:web resolver through WEB.fetch, the same way test/test.js simulates hosting.
   Signing and verification reuse ../js/vc.js, did-web.js and vp.js unchanged. */
"use strict";

const V2_CONTEXT = "https://www.w3.org/ns/credentials/v2";
const STATUS_BITS = 131072; // W3C Bitstring Status List minimum length (16 KB), so one index reveals little
const PLATFORM_ORIGIN = "https://dpp-platform.example";
const nowIso = () => new Date().toISOString();
const toHex = (bytes) => [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
const credType = (vc) => [].concat(vc?.type ?? []).filter((t) => t !== "VerifiableCredential").at(-1) ?? "VerifiableCredential";

/* ---------- Store: the platform database ---------- */
const Store = {
  key: "dppPlatform.v1",
  state: null,
  load() {
    try { this.state = JSON.parse(localStorage.getItem(this.key)); } catch { this.state = null; }
    return this.state;
  },
  save() {
    try { localStorage.setItem(this.key, JSON.stringify(this.state)); } catch (e) { console.warn("無法寫入 localStorage：", e); }
  },
  reset() {
    try { localStorage.removeItem(this.key); } catch {}
    this.state = null;
  },
  fresh() {
    return { version: 1, createdAt: nowIso(), orgs: {}, kms: {}, trust: [], models: {}, items: {}, passports: {},
      credentials: {}, statusLists: {}, registry: {}, audit: [], ui: { org: "fantech" } };
  },
  org(id) {
    const o = this.state.orgs[id];
    if (!o) throw new Error("找不到組織：" + id);
    return o;
  },
  orgByDid(did) { return Object.values(this.state.orgs).find((o) => o.did === did); },
};

/* ---------- Hosting: what the platform serves over HTTPS (CDN) ---------- */
const Hosting = {
  files: new Map(), // https URL → JSON document
  put(url, doc) { this.files.set(url, doc); },
  get(url) { return this.files.get(url); },
  // Platform-hosted URLs are answered locally; other *.example hosts don't exist; everything else is real network
  fetch(url, opts) {
    const u = String(url);
    if (Hosting.files.has(u)) {
      return Promise.resolve(new Response(JSON.stringify(Hosting.files.get(u)), { status: 200, headers: { "content-type": "application/json" } }));
    }
    let host = "";
    try { host = new URL(u).hostname; } catch {}
    if (host.endsWith(".example")) return Promise.resolve(new Response("Not Found", { status: 404 }));
    return globalThis.fetch(url, opts);
  },
};
WEB.fetch = Hosting.fetch;

/* ---------- Audit ledger: append-only, each entry hashes the previous one ---------- */
const Audit = {
  async append(actor, action, target) {
    const log = Store.state.audit;
    const entry = { seq: log.length + 1, at: nowIso(), actor, action, target, prevHash: log.at(-1)?.hash ?? "0".repeat(64) };
    entry.hash = toHex(await sha256(jcs(entry)));
    log.push(entry);
  },
  // Recompute every hash; the first mismatch is where the ledger was altered
  async verify() {
    let prev = "0".repeat(64);
    for (const e of Store.state.audit) {
      const { hash, ...body } = e;
      if (body.prevHash !== prev || toHex(await sha256(jcs(body))) !== hash) return { ok: false, brokenAt: e.seq };
      prev = hash;
    }
    return { ok: true, count: Store.state.audit.length };
  },
};

/* ---------- KMS + signing service ---------- */
// Stand-in for an HSM: private keys are "sealed" as JWK in localStorage and unsealed as non-extractable CryptoKeys.
// A real deployment never stores private key material outside the HSM.
const KMS = {
  handles: new Map(), // verificationMethod id → CryptoKey (sign only)
  keysOf(orgId) { return Object.values(Store.state.kms).filter((k) => k.orgId === orgId); },
  activeKey(orgId) { return this.keysOf(orgId).find((k) => k.state === "active"); },
  async create(orgId) {
    const org = Store.org(orgId);
    const { privateKey, pub } = await generateEd25519(true);
    const jwk = await crypto.subtle.exportKey("jwk", privateKey);
    const id = `${org.did}#key-${this.keysOf(orgId).length + 1}`;
    Store.state.kms[id] = { id, orgId, alg: "Ed25519", publicKeyMultibase: ed25519Multibase(pub), state: "active",
      createdAt: nowIso(), sealed: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d } };
    await this.unsealOne(Store.state.kms[id]);
    return Store.state.kms[id];
  },
  async unsealOne(k) {
    this.handles.set(k.id, await crypto.subtle.importKey("jwk", { ...k.sealed }, ED25519, false, ["sign"]));
  },
  async unsealAll() {
    for (const k of Object.values(Store.state.kms)) if (k.state !== "revoked" && !this.handles.has(k.id)) await this.unsealOne(k);
  },
  signingKeys(orgId) {
    const org = Store.org(orgId), key = this.activeKey(orgId);
    if (!key) throw new Error(`${org.name} 沒有可用的簽章金鑰`);
    return { did: org.did, cryptosuite: "eddsa-jcs-2022", privateKey: this.handles.get(key.id), verificationMethod: key.id };
  },
};

const Signer = {
  // Only the active key signs; the private key never leaves KMS (createProof gets a handle, not key bytes)
  async sign(orgId, unsigned, options) {
    const keys = KMS.signingKeys(orgId);
    const proof = await createProof(unsigned, keys, undefined, options);
    await Audit.append(orgId, "簽章", `${credType(unsigned)}（#${fragmentOf(keys.verificationMethod)}）`);
    return { ...unsigned, proof };
  },
};

/* ---------- DID service: did:web documents, key rotation, key history ---------- */
const DidService = {
  url(org) { return DID_METHODS["did:web:"].parse(org.did).url; },
  // Retired keys stay listed so credentials they signed keep verifying; revoked keys disappear
  document(org) {
    const keys = KMS.keysOf(org.id).filter((k) => k.state !== "revoked");
    const ids = keys.map((k) => k.id);
    return {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
      id: org.did,
      verificationMethod: keys.map((k) => ({ id: k.id, type: "Multikey", controller: org.did, publicKeyMultibase: k.publicKeyMultibase })),
      authentication: ids,
      assertionMethod: ids,
    };
  },
  publish(org) { Hosting.put(this.url(org), this.document(org)); },
  publishAll() { for (const o of Object.values(Store.state.orgs)) this.publish(o); },
  async rotate(orgId) {
    const old = KMS.activeKey(orgId);
    if (old) old.state = "retired";
    const k = await KMS.create(orgId);
    this.publish(Store.org(orgId));
    await Audit.append(orgId, "金鑰輪替", `#${fragmentOf(old?.id ?? "")} 退役，#${fragmentOf(k.id)} 啟用`);
    Store.save();
    return k;
  },
  // Revoking a key removes it from did.json: everything it signed stops verifying (used after a key compromise)
  async revoke(keyId) {
    const k = Store.state.kms[keyId];
    const wasActive = k.state === "active";
    k.state = "revoked";
    delete k.sealed;
    KMS.handles.delete(keyId);
    if (wasActive) await KMS.create(k.orgId);
    this.publish(Store.org(k.orgId));
    await Audit.append(k.orgId, "金鑰撤銷", `#${fragmentOf(keyId)} 自 DID 文件移除`);
    // Status lists are live documents: re-sign the ones this key signed, or every credential pointing at them breaks
    for (const list of Object.values(Store.state.statusLists)) {
      if (list.orgId === k.orgId && list.vc?.proof?.verificationMethod === keyId) await StatusService.publish(list);
    }
    Store.save();
  },
};

/* ---------- Status service: W3C Bitstring Status List ---------- */
const StatusService = {
  url(org, purpose) { return `https://status.dpp-platform.example/${org.id}/${purpose}`; },
  list(orgId, purpose) {
    const id = `${orgId}:${purpose}`;
    return (Store.state.statusLists[id] ??= { id, orgId, purpose, url: this.url(Store.org(orgId), purpose), set: [], used: [], vc: null });
  },
  // Random indexes, so neighbouring credentials can't be correlated by position
  async allocate(orgId, purpose) {
    const list = this.list(orgId, purpose);
    let idx;
    do idx = crypto.getRandomValues(new Uint32Array(1))[0] % STATUS_BITS; while (list.used.includes(idx));
    list.used.push(idx);
    if (!list.vc) await this.publish(list);
    return { id: `${list.url}#${idx}`, type: "BitstringStatusListEntry", statusPurpose: purpose, statusListIndex: String(idx), statusListCredential: list.url };
  },
  // Index 0 is the left-most bit of the first byte; the list is GZIP-compressed and multibase base64url ("u") encoded
  async encode(set) {
    const bits = new Uint8Array(STATUS_BITS / 8);
    for (const i of set) bits[i >> 3] |= 0x80 >> (i & 7);
    const gz = new Uint8Array(await new Response(new Blob([bits]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer());
    return "u" + base64urlEncode(gz);
  },
  async decode(encodedList) {
    if (typeof encodedList !== "string" || !encodedList.startsWith("u")) throw new Error("encodedList 應為 u 開頭的 multibase base64url");
    const raw = base64urlDecode(encodedList.slice(1));
    return new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream("gzip"))).arrayBuffer());
  },
  async publish(list) {
    const org = Store.org(list.orgId);
    list.vc = await Signer.sign(list.orgId, {
      "@context": [V2_CONTEXT],
      id: list.url,
      type: ["VerifiableCredential", "BitstringStatusListCredential"],
      issuer: org.did,
      validFrom: nowIso(),
      credentialSubject: { id: list.url + "#list", type: "BitstringStatusList", statusPurpose: list.purpose, encodedList: await this.encode(list.set) },
    });
    Hosting.put(list.url, list.vc);
  },
  publishAll() { for (const l of Object.values(Store.state.statusLists)) if (l.vc) Hosting.put(l.url, l.vc); },
  isSet(entry) {
    const list = Object.values(Store.state.statusLists).find((l) => l.url === entry.statusListCredential);
    return !!list?.set.includes(Number(entry.statusListIndex));
  },
  async set(entry, on) {
    const list = Object.values(Store.state.statusLists).find((l) => l.url === entry.statusListCredential);
    const idx = Number(entry.statusListIndex);
    list.set = on ? [...new Set([...list.set, idx])] : list.set.filter((i) => i !== idx);
    await this.publish(list);
  },
};

/* ---------- Trust registry (EBSI-style: RootTAO → TAO → TI) ---------- */
const ROLE_NAMES = { RootTAO: "根信任機構", TAO: "認證機構", TI: "受信任發證者", Operator: "經濟業者" };
const Trust = {
  find(did) { return Store.state.trust.find((e) => e.did === did); },
  async register(parentOrgId, childOrgId, role, types) {
    const child = Store.org(childOrgId);
    let accreditation = null;
    if (parentOrgId) {
      const vc = await Signer.sign(parentOrgId, {
        "@context": [V2_CONTEXT],
        id: "urn:uuid:" + crypto.randomUUID(),
        type: ["VerifiableCredential", "VerifiableAccreditation"],
        issuer: Store.org(parentOrgId).did,
        validFrom: nowIso(),
        credentialSubject: { id: child.did, name: child.name, role, accreditedFor: types },
        credentialStatus: await StatusService.allocate(parentOrgId, "revocation"),
      });
      Store.state.credentials[vc.id] = { vc, kind: "accreditation", issuerOrg: parentOrgId, holderOrg: childOrgId, createdAt: nowIso() };
      accreditation = vc.id;
    }
    Store.state.trust.push({ did: child.did, orgId: childOrgId, role, types, accreditedBy: parentOrgId ? Store.org(parentOrgId).did : null, accreditation, since: nowIso() });
    await Audit.append(parentOrgId ?? childOrgId, "信任登錄", `${child.name} 登錄為 ${ROLE_NAMES[role]}`);
  },
  /* Walk accreditedBy up to the root; every accreditation credential on the way must verify and be unrevoked */
  async chain(did, type) {
    const steps = [];
    let e = this.find(did);
    if (!e) return { ok: false, steps, reason: "發證者不在平台信任註冊處（可能是自架的假發證者）" };
    if (type && !e.types.includes(type) && !e.types.includes("*")) {
      return { ok: false, steps: [e], reason: `${ROLE_NAMES[e.role]} ${Store.orgByDid(did)?.name ?? did} 未被授權簽發 ${type}` };
    }
    for (let guard = 0; e && guard < 8; guard++) {
      steps.push(e);
      if (e.role === "RootTAO") return { ok: true, steps };
      const acc = Store.state.credentials[e.accreditation]?.vc;
      const r = acc ? await verifyProof(acc) : { fails: ["找不到認可憑證"] };
      if (r.fails.length) return { ok: false, steps, reason: `${Store.orgByDid(e.did)?.name} 的認可憑證驗證失敗：${r.fails[0]}` };
      if (acc.credentialStatus && StatusService.isSet(acc.credentialStatus)) return { ok: false, steps, reason: `${Store.orgByDid(e.did)?.name} 的認可已被撤銷` };
      e = this.find(e.accreditedBy);
    }
    return { ok: false, steps, reason: "信任鏈沒有連到根信任機構" };
  },
};

/* ---------- Issuance: ISO certificates, repairer authorisations ---------- */
const Issuance = {
  record(vc, kind, issuerOrg, holderOrg, extra = {}) {
    Store.state.credentials[vc.id] = { vc, kind, issuerOrg, holderOrg, createdAt: nowIso(), ...extra };
    return Store.state.credentials[vc.id];
  },
  async issueIso(cbId, holderId, { standard, number, scope, validUntil, site }) {
    if (!standard || !number || !scope || !validUntil) throw new Error("標準、證書編號、範圍、到期日都必填");
    const cb = Store.org(cbId), holder = Store.org(holderId);
    const vc = await Signer.sign(cbId, {
      "@context": [V2_CONTEXT],
      id: "urn:uuid:" + crypto.randomUUID(),
      type: ["VerifiableCredential", "IsoCertificationCredential"],
      issuer: cb.did,
      validFrom: nowIso(),
      validUntil: /^\d{4}-\d{2}-\d{2}$/.test(validUntil) ? validUntil + "T00:00:00Z" : validUntil,
      credentialSubject: { id: holder.did, name: holder.name, certificationStandard: standard, certificateNumber: number, scope, ...(site && { site }) },
      credentialStatus: [await StatusService.allocate(cbId, "revocation"), await StatusService.allocate(cbId, "suspension")],
    });
    this.record(vc, "iso", cbId, holderId);
    await Audit.append(cbId, "簽發證書", `${standard} ${number} → ${holder.name}`);
    Store.save();
    return vc;
  },
  async issueRepairer(brandId, repairerId, { scope }) {
    const brand = Store.org(brandId), rep = Store.org(repairerId);
    const vc = await Signer.sign(brandId, {
      "@context": [V2_CONTEXT],
      id: "urn:uuid:" + crypto.randomUUID(),
      type: ["VerifiableCredential", "AuthorizedRepairerCredential"],
      issuer: brand.did,
      validFrom: nowIso(),
      validUntil: new Date(Date.now() + 365 * 864e5).toISOString(),
      credentialSubject: { id: rep.did, name: rep.name, authorizedBy: brand.name, scope: scope || "全系列產品" },
      credentialStatus: await StatusService.allocate(brandId, "revocation"),
    });
    this.record(vc, "repairer", brandId, repairerId);
    await Audit.append(brandId, "授權維修商", rep.name);
    Store.save();
    return vc;
  },
  heldBy(orgId, kind) { return Object.values(Store.state.credentials).filter((c) => c.holderOrg === orgId && (!kind || c.kind === kind)); },
  issuedBy(orgId, kind) { return Object.values(Store.state.credentials).filter((c) => c.issuerOrg === orgId && (!kind || c.kind === kind)); },
  entries(vc) { return [].concat(vc.credentialStatus ?? []); },
  // "active" | "suspended" | "revoked", read from the published status lists
  statusOf(vc) {
    const es = this.entries(vc);
    if (es.some((e) => e.statusPurpose === "revocation" && StatusService.isSet(e))) return "revoked";
    if (es.some((e) => e.statusPurpose === "suspension" && StatusService.isSet(e))) return "suspended";
    return "active";
  },
  async setStatus(vcId, purpose, on) {
    const rec = Store.state.credentials[vcId];
    const entry = this.entries(rec.vc).find((e) => e.statusPurpose === purpose);
    if (!entry) throw new Error(`這張憑證沒有 ${purpose} 狀態欄位`);
    await StatusService.set(entry, on);
    const s = rec.vc.credentialSubject;
    const what = { revocation: on ? "撤銷" : "取消撤銷", suspension: on ? "暫停" : "恢復" }[purpose];
    await Audit.append(rec.issuerOrg, what, `${s.certificationStandard ?? credType(rec.vc)} ${s.certificateNumber ?? s.name ?? ""}`);
    Store.save();
  },
};

/* ---------- Catalog: models (GTIN) and items (serial) ---------- */
const Catalog = {
  // GS1 mod-10 check digit over the first 13 digits of a GTIN-14
  checkDigit(body13) {
    const sum = [...body13].reverse().reduce((s, d, i) => s + Number(d) * (i % 2 === 0 ? 3 : 1), 0);
    return String((10 - (sum % 10)) % 10);
  },
  gtin14(input) {
    let d = String(input).replace(/\D/g, "");
    if (d.length === 13) d = "0" + d; // GTIN-13 → GTIN-14 keeps the same check digit
    if (d.length !== 14) throw new Error("GTIN 應為 13 或 14 位數字");
    if (this.checkDigit(d.slice(0, 13)) !== d[13]) throw new Error(`GTIN 檢查碼錯誤（應為 ${this.checkDigit(d.slice(0, 13))}）`);
    return d;
  },
  upi(orgId, gtin, serial) { return `https://${Store.org(orgId).resolver}/01/${gtin}/21/${encodeURIComponent(serial)}`; },
  addModel(orgId, { gtin, name, category }) {
    const g = this.gtin14(gtin);
    if (Store.state.models[g]) throw new Error("這個 GTIN 已經存在");
    if (!name) throw new Error("請填產品名稱");
    Store.state.models[g] = { gtin: g, orgId, name, category, createdAt: nowIso() };
    return Store.state.models[g];
  },
  async addItem(orgId, { gtin, serial, facility, madeOn }) {
    const model = Store.state.models[gtin];
    if (!model || model.orgId !== orgId) throw new Error("請選擇自己的產品型號");
    if (!serial) throw new Error("請填序號");
    const upi = this.upi(orgId, gtin, serial);
    if (Store.state.items[upi]) throw new Error("這個序號已經存在");
    Store.state.items[upi] = { upi, gtin, serial, facility: facility || "", madeOn: madeOn || "", createdAt: nowIso() };
    await Audit.append(orgId, "建立單品", `${model.name} ${serial}`);
    Passports.create(upi);
    Store.save();
    return Store.state.items[upi];
  },
  itemsOf(orgId) {
    return Object.values(Store.state.items).filter((i) => Store.state.models[i.gtin]?.orgId === orgId);
  },
  byPath(gtin, serial) { return Object.values(Store.state.items).find((i) => i.gtin === gtin && i.serial === serial); },
};

/* ---------- Passport service ---------- */
const TIERS = { public: "公開", restricted: "受限（維修、回收）", authority: "機關" };
const CATEGORY_TEMPLATES = {
  "電子產品": [
    ["material", "主要材料", "鋁合金 62%、PC/ABS 21%、銅 9%、其他 8%", "", "public"],
    ["recycled", "再生料比例", "18", "%", "public"],
    ["carbon", "產品碳足跡", "41.6", "kg CO₂e", "public"],
    ["repairability", "可修復性指數", "7.8", "/ 10", "public"],
    ["warranty", "保固", "3", "年", "public"],
    ["disassembly", "拆解步驟", "1. 移除底部 4 顆 T10 螺絲　2. 拆下風扇模組　3. 拔除主電源排線", "", "restricted"],
    ["spareParts", "備品料號", "FAN-80-12V、PCB-PSU-650-R2", "", "restricted"],
    ["hazard", "有害物質位置", "主電容（含電解液）位於主板右側", "", "restricted"],
    ["conformity", "符合性聲明", "EU DoC 2026-0142（LVD、EMC、RoHS）", "", "authority"],
  ],
  "電池": [
    ["chemistry", "電池化學", "鋰離子 NMC 811", "", "public"],
    ["capacity", "額定容量", "10000", "mAh", "public"],
    ["carbon", "產品碳足跡", "12.3", "kg CO₂e", "public"],
    ["recycledCo", "再生鈷比例", "16", "%", "public"],
    ["cycles", "預期循環壽命", "800", "次", "public"],
    ["soh", "健康狀態量測方法", "依 IEC 62660-1 容量測試", "", "restricted"],
    ["dismantling", "拆解與安全", "放電至 0% 後再拆，電芯以膠固定需加熱至 60°C", "", "restricted"],
    ["dueDiligence", "供應鏈盡職調查報告", "DD-2026-PB10K（鈷、鋰、鎳）", "", "authority"],
  ],
};

const Passports = {
  create(upi) {
    const item = Store.state.items[upi], model = Store.state.models[item.gtin];
    const id = "pp-" + crypto.randomUUID().slice(0, 8);
    const attrs = (CATEGORY_TEMPLATES[model.category] ?? []).map(([key, label, value, unit, tier]) => ({ key, label, value, unit, tier }));
    Store.state.passports[id] = { id, upi, state: "draft", versions: [], draft: { attributes: attrs, certIds: [] }, createdAt: nowIso() };
    return Store.state.passports[id];
  },
  ofItem(upi) { return Object.values(Store.state.passports).find((p) => p.upi === upi); },
  saveDraft(id, { attributes, certIds }) {
    const p = Store.state.passports[id];
    p.draft = { attributes, certIds };
    Store.save();
  },
  // The ISO certificate is linked by id plus an SRI digest of its JCS form, so a swapped certificate is detected
  async certLink(vc) {
    const digest = btoa(String.fromCharCode(...(await sha256(jcs(vc)))));
    return { id: vc.id, mediaType: "application/vc", digestSRI: "sha256-" + digest };
  },
  async publish(id) {
    const p = Store.state.passports[id];
    const item = Store.state.items[p.upi], model = Store.state.models[item.gtin], org = Store.org(model.orgId);
    if (!p.draft.attributes.some((a) => a.tier === "public" && a.value)) throw new Error("至少要有一個公開欄位");
    const reg = await Registry.register(p.upi, org.id);
    const version = p.versions.length + 1;
    const pick = (tier) => p.draft.attributes.filter((a) => a.tier === tier && a.value).map(({ key, label, value, unit }) => ({ key, label, value, ...(unit && { unit }) }));
    const certs = p.draft.certIds.map((cid) => Store.state.credentials[cid]?.vc).filter(Boolean);
    const vc = await Signer.sign(org.id, {
      "@context": [V2_CONTEXT],
      id: "urn:uuid:" + crypto.randomUUID(),
      type: ["VerifiableCredential", "DigitalProductPassportCredential"],
      issuer: org.did,
      validFrom: nowIso(),
      credentialSubject: {
        id: p.upi,
        type: "Product",
        gtin: item.gtin,
        serialNumber: item.serial,
        name: model.name,
        category: model.category,
        manufacturer: { id: org.did, name: org.name },
        ...(item.facility && { facility: item.facility }),
        ...(item.madeOn && { manufacturedOn: item.madeOn }),
        registrationId: reg.registrationId,
        passportVersion: version,
        attributes: pick("public"),
      },
      ...(certs.length && { relatedResource: await Promise.all(certs.map((c) => this.certLink(c))) }),
      credentialStatus: await StatusService.allocate(org.id, "revocation"),
    });
    Issuance.record(vc, "passport", org.id, null, { upi: p.upi });
    // Restricted tiers are separate credentials, released only after the policy decision allows it
    const sections = {};
    for (const tier of ["restricted", "authority"]) {
      const attrs = pick(tier);
      if (!attrs.length) continue;
      const s = await Signer.sign(org.id, {
        "@context": [V2_CONTEXT],
        id: "urn:uuid:" + crypto.randomUUID(),
        type: ["VerifiableCredential", "PassportRestrictedSection"],
        issuer: org.did,
        validFrom: nowIso(),
        credentialSubject: { id: p.upi, tier, passport: vc.id, attributes: attrs },
        credentialStatus: await StatusService.allocate(org.id, "revocation"),
      });
      Issuance.record(s, "section", org.id, null, { upi: p.upi, tier });
      sections[tier] = s.id;
    }
    p.versions.push({ version, vcId: vc.id, sections, signedAt: nowIso(), registrationId: reg.registrationId });
    p.state = "published";
    await Audit.append(org.id, "發布護照", `${model.name} ${item.serial} v${version}`);
    Store.save();
    return vc;
  },
  latest(p) { return p?.versions.at(-1); },
  // Everything the public scan page needs, or null when the item has no published passport
  publicView(gtin, serial) {
    const item = Catalog.byPath(gtin, serial);
    if (!item) return null;
    const p = this.ofItem(item.upi), v = this.latest(p);
    if (!v) return { item, model: Store.state.models[item.gtin], passport: p, vc: null };
    return { item, model: Store.state.models[item.gtin], passport: p, version: v, vc: Store.state.credentials[v.vcId].vc };
  },
  affectedBy(certId) {
    return Object.values(Store.state.passports).filter((p) => {
      const vc = Store.state.credentials[this.latest(p)?.vcId]?.vc;
      return vc?.relatedResource?.some((r) => r.id === certId);
    });
  },
};

/* ---------- EU DPP registry (mock): unique identifier registration ---------- */
const Registry = {
  async register(upi, orgId) {
    const existing = Store.state.registry[upi];
    if (existing) return existing;
    const registrationId = "EU-DPP-" + toHex(crypto.getRandomValues(new Uint8Array(5))).toUpperCase();
    Store.state.registry[upi] = { upi, registrationId, operatorDid: Store.org(orgId).did, registeredAt: nowIso() };
    await Audit.append(orgId, "註冊處登記", `${upi} → ${registrationId}`);
    return Store.state.registry[upi];
  },
};

/* ---------- Verification service: the four questions ---------- */
const Verify = {
  /* Returns { verdict: "valid" | "warning" | "invalid", checks: [{ key, label, status, detail, lines? }], linked: [] } */
  async credential(vc, { depth = 0 } = {}) {
    const checks = [];
    const add = (key, label, status, detail, lines) => checks.push({ key, label, status, detail, lines });
    if (!isPlainObject(vc)) return { verdict: "invalid", checks: [{ key: "format", label: "格式", status: "fail", detail: "不是 JSON 物件" }], linked: [] };

    // 1. Signature (plus the VC 2.0 structure the signature depends on)
    const r = report();
    r.check([].concat(vc["@context"])[0] === V2_CONTEXT, "@context 為 W3C VC 2.0", "@context 第一項必須是 W3C VC 2.0");
    r.check([].concat(vc.type).includes("VerifiableCredential"), "type 含 VerifiableCredential", "type 必須包含 VerifiableCredential");
    if (vc.proof === undefined) r.fails.push("沒有 proof：無法確認是誰簽發");
    else {
      const pr = await verifyProof(vc);
      r.fails.push(...pr.fails); r.warns.push(...pr.warns); r.passes.push(...pr.passes);
    }
    add("signature", "簽章正確、內容未被竄改", r.fails.length ? "fail" : r.warns.length ? "warn" : "pass",
      r.fails[0] ?? r.warns[0] ?? `由 #${fragmentOf(vc.proof.verificationMethod).replace(/^(.{14}).{4,}$/, "$1…")} 簽署（${vc.proof.cryptosuite}）`, [...r.fails, ...r.warns, ...r.passes]);

    // 2. Issuer trust
    const type = credType(vc);
    const t = await Trust.chain(typeof vc.issuer === "string" ? vc.issuer : vc.issuer?.id, type);
    add("trust", "發證者在信任鏈上", t.ok ? "pass" : "fail",
      t.ok ? t.steps.map((s) => Store.orgByDid(s.did)?.name ?? s.did).join(" ← ") : t.reason);

    // 3. Status lists
    const entries = [].concat(vc.credentialStatus ?? []);
    if (!entries.length) add("status", "沒有被撤銷或暫停", "warn", "沒有 credentialStatus，無法確認是否已被撤銷");
    else {
      let status = "pass", detail = "狀態清單查詢：有效";
      for (const e of entries) {
        const res = await this.statusEntry(vc, e);
        if (res.status !== "pass" && status !== "fail") { status = res.status; detail = res.detail; }
      }
      add("status", "沒有被撤銷或暫停", status, detail);
    }

    // 4. Validity period
    const now = Date.now(), from = Date.parse(vc.validFrom), until = Date.parse(vc.validUntil);
    if (!isNaN(from) && now < from) add("validity", "在有效期內", "fail", `尚未生效（${vc.validFrom.slice(0, 10)} 起）`);
    else if (!isNaN(until) && now > until) add("validity", "在有效期內", "fail", `已於 ${vc.validUntil.slice(0, 10)} 到期`);
    else add("validity", "在有效期內", "pass", isNaN(until) ? "沒有到期日" : `有效至 ${vc.validUntil.slice(0, 10)}`);

    // Linked certificates (one level): found by id, checked against the digest the passport signed
    const linked = [];
    if (depth === 0) {
      for (const rel of [].concat(vc.relatedResource ?? [])) {
        const cert = Store.state.credentials[rel.id]?.vc;
        if (!cert) { linked.push({ rel, cert: null, result: null, digestOk: false }); continue; }
        const digestOk = (await Passports.certLink(cert)).digestSRI === rel.digestSRI;
        linked.push({ rel, cert, digestOk, result: await this.credential(cert, { depth: 1 }) });
      }
    }
    const fails = checks.some((c) => c.status === "fail");
    const warns = checks.some((c) => c.status === "warn") || linked.some((l) => !l.digestOk || l.result?.verdict !== "valid");
    return { verdict: fails ? "invalid" : warns ? "warning" : "valid", checks, linked };
  },

  async statusEntry(vc, e) {
    const listVc = Hosting.get(e.statusListCredential);
    if (!listVc) return { status: "warn", detail: `取不到狀態清單 ${e.statusListCredential}` };
    const pr = await verifyProof(listVc);
    if (pr.fails.length) return { status: "fail", detail: "狀態清單本身的簽章無效：" + pr.fails[0] };
    if (listVc.issuer !== vc.issuer) return { status: "fail", detail: "狀態清單不是同一個發證者發布的" };
    const bits = await StatusService.decode(listVc.credentialSubject.encodedList);
    const i = Number(e.statusListIndex);
    const on = (bits[i >> 3] & (0x80 >> (i & 7))) !== 0;
    if (!on) return { status: "pass", detail: "狀態清單查詢：有效" };
    return { status: "fail", detail: e.statusPurpose === "suspension" ? "已被發證者暫停" : "已被發證者撤銷" };
  },
};

/* ---------- Authorised access: OID4VP-style exchange + policy decision point ---------- */
const POLICY = {
  roles: { AuthorizedRepairerCredential: "repairer" },
  tiers: { consumer: ["public"], repairer: ["public", "restricted"], authority: ["public", "restricted", "authority"] },
  names: { consumer: "一般大眾", repairer: "授權維修商", authority: "主管機關" },
};

const Access = {
  verifier: new Verifier(PLATFORM_ORIGIN, { ttlMs: 120000 }),
  request() { return this.verifier.createRequest(); },
  // The holder's wallet signs a VP bound to the request (challenge + domain) with its authentication key
  async present(holderOrgId, request, vcIds) {
    const holder = Store.org(holderOrgId);
    const vp = buildVp(holder.did, vcIds.map((id) => Store.state.credentials[id].vc));
    return Signer.sign(holderOrgId, vp, { proofPurpose: "authentication", challenge: request.challenge, domain: request.domain });
  },
  /* Verify the VP, then the credentials' trust and status, then ask the policy which tiers this role may read */
  async exchange(vp, upi) {
    const r = await this.verifier.verify(vp);
    const steps = [{ label: "VP 簽章、nonce、受眾", ok: !r.fails.length, detail: r.fails[0] ?? "持有人簽章正確，challenge 第一次使用，受眾是本平台" }];
    if (r.fails.length) return { ok: false, steps, errors: r.errors.map((e) => e.name), report: r };
    let role = "consumer";
    for (const vc of vp.verifiableCredential) {
      const res = await Verify.credential(vc);
      const ok = res.verdict !== "invalid";
      steps.push({ label: `資格憑證 ${credType(vc)}`, ok, detail: ok ? `發證者可信、狀態有效（${Store.orgByDid(vc.issuer)?.name}）` : res.checks.find((c) => c.status === "fail").detail });
      if (ok && POLICY.roles[credType(vc)]) role = POLICY.roles[credType(vc)];
    }
    const tiers = POLICY.tiers[role];
    steps.push({ label: "授權決策（PDP）", ok: role !== "consumer", detail: `角色：${POLICY.names[role]}；可讀：${tiers.map((t) => TIERS[t]).join("、")}` });
    if (role === "consumer") return { ok: false, steps, errors: ["AccessDenied"] };
    const p = Passports.ofItem(upi), v = Passports.latest(p);
    const sections = tiers.filter((t) => v?.sections?.[t]).map((t) => Store.state.credentials[v.sections[t]].vc);
    await Audit.append(Store.orgByDid(vp.holder)?.id ?? vp.holder, "讀取受限欄位", `${upi}（${tiers.filter((t) => t !== "public").join("、")}）`);
    Store.save();
    return { ok: true, steps, role, sections };
  },
};

/* ---------- Boot ---------- */
async function bootPlatform(onProgress = () => {}) {
  if (!Store.load()) {
    Store.state = Store.fresh();
    await seedPlatform(onProgress);
    Store.save();
  } else {
    await KMS.unsealAll();
  }
  DidService.publishAll();
  StatusService.publishAll();
}
