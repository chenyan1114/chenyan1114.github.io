/* Mock backend of the product-grade DPP platform. Each object stands for one service in the architecture plan:
   Store (PostgreSQL), Hosting (CDN), KMS + Signer (HSM), DidService, StatusService (Bitstring Status List),
   Trust (trust registry), Issuance, Catalog, Passports, Registry (EU DPP registry), Verify, Access (OID4VP-style
   exchange + policy decision), Audit (hash-chained ledger), Anchor (the ledger's head, attested on Sepolia through
   EAS) and StatusLedger (every status list version's digest, attested the same way). Anchor and StatusLedger are
   the only parts that touch a real blockchain.
   State lives in localStorage. Files the platform publishes (did.json, status lists) are served to the official
   did:web resolver through WEB.fetch, the same way test/test.js simulates hosting.
   Credentials are built, signed and checked through ../js/vc-engine.js (VcEngine); passports, GS1 paths, field
   tiers and the role policy come from ../js/dpp-engine.js (DppEngine). The services here add storage, keys, trust
   and the platform's own workflow on top. */
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
      credentials: {}, statusLists: {}, registry: {}, audit: [], anchors: [], anchorAccount: null, listAnchors: {}, ui: { org: "fantech" } };
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
  // Recompute every hash (up to entry upTo); the first mismatch is where the ledger was altered
  async verify(upTo = Infinity) {
    let prev = "0".repeat(64);
    for (const e of Store.state.audit) {
      if (e.seq > upTo) break;
      const { hash, ...body } = e;
      if (body.prevHash !== prev || toHex(await sha256(jcs(body))) !== hash) return { ok: false, brokenAt: e.seq };
      prev = hash;
    }
    return { ok: true, count: Math.min(upTo, Store.state.audit.length) };
  },
  // What an insider with database access can do: recompute every hash from entry `index` on, so verify() passes again
  async rehashFrom(index) {
    const log = Store.state.audit;
    for (let i = index; i < log.length; i++) {
      const { hash, ...body } = log[i];
      body.prevHash = log[i - 1]?.hash ?? "0".repeat(64);
      log[i] = { ...body, hash: toHex(await sha256(jcs(body))) };
    }
  },
};

/* One attestation read back from the chain (Sepolia through EAS.reader, swappable in tests) */
async function readAttestation(uid) {
  const reader = EAS.reader();
  try {
    const att = await reader.attestation(uid);
    if (!att) throw new Error("鏈上找不到這筆 attestation（交易可能還沒確認，稍後再試）");
    return att;
  } finally {
    reader.close?.();
  }
}

/* ---------- Anchor: the audit chain's head, attested on Sepolia through EAS (../js/eas.js) ---------- */
// The hash chain alone can't stop the platform itself from rewriting history: edit an entry, recompute every later
// hash (Audit.rehashFrom) and verify() passes again. A head attested on a public chain can't be recomputed, so the
// rewrite shows. One transaction covers every entry up to that head, however many there are. The anchoring account
// is published in the platform's did.json (service #anchor-account), so verifiers know whose attestations count.
const Anchor = {
  list() { return (Store.state.anchors ??= []); },
  account() { return Store.state.anchorAccount ?? null; },
  // What a verifier sees: the account published in the platform's did.json
  publishedAccount() {
    const root = Object.values(Store.state.orgs).find((o) => o.kind === "root");
    const svc = root && Hosting.get(DidService.url(root))?.service?.find((x) => x.type === "DppAnchorAccount");
    return svc ? String(svc.serviceEndpoint).split(":").pop() : null;
  },
  // The first anchoring transaction (audit or status lists) fixes the account; later ones must come from it
  claim(wallet) {
    const acct = this.account();
    if (acct && acct.toLowerCase() !== wallet.address.toLowerCase()) throw new Error(`錨定帳戶是 ${acct}，請用這個帳戶連接 MetaMask`);
  },
  adopt(wallet) {
    if (this.account()) return;
    Store.state.anchorAccount = wallet.address;
    DidService.publish(Object.values(Store.state.orgs).find((o) => o.kind === "root"));
  },
  head() { const e = Store.state.audit.at(-1); return e ? { seq: e.seq, hash: e.hash } : null; },
  pending() { return Store.state.audit.length - (this.list().at(-1)?.seq ?? 0); },
  async anchor(wallet) {
    if (!(await Audit.verify()).ok) throw new Error("稽核帳本的雜湊鏈已經斷掉，不能把壞掉的鏈頭錨定上鏈");
    this.claim(wallet);
    const head = this.head();
    if (this.list().at(-1)?.seq === head.seq) throw new Error(`第 ${head.seq} 筆已經錨定過，等有新的稽核紀錄再錨定`);
    const reader = EAS.reader();
    try { await easEnsureSchema(wallet, "anchor", reader); } finally { reader.close?.(); }
    const res = await easAttest(wallet, "anchor", ["0x" + head.hash, head.seq]);
    this.adopt(wallet);
    this.list().push({ seq: head.seq, head: head.hash, uid: res.uid, tx: res.hash, block: res.block, at: nowIso() });
    await Audit.append("platform", "錨定上鏈", `第 ${head.seq} 筆的鏈頭 ${head.hash.slice(0, 10)}… → EAS`);
    Store.save();
    return this.list().at(-1);
  },
  /* Server mode: a browser wallet already sent the attestation; read it back from the chain and record it only if
     it is an anchor schema attestation by the anchoring account whose hash equals this platform's ledger entry */
  async accept(uid, { tx, block } = {}) {
    if (this.list().some((a) => a.uid === uid)) throw new Error("這筆錨定已經登記過");
    const att = await readAttestation(uid);
    if (att.schema !== easSchemaUid("anchor")) throw new Error("這筆 attestation 不是稽核錨定的 schema");
    const acct = this.account();
    if (acct && acct.toLowerCase() !== att.attester.toLowerCase()) throw new Error(`錨定帳戶是 ${acct}，這筆是 ${att.attester} 寫的`);
    const [head, seq] = easDecode("anchor", att.data);
    const n = Number(seq), entry = Store.state.audit[n - 1], chain = await Audit.verify(n);
    if (!entry || !chain.ok || "0x" + entry.hash !== head.toLowerCase()) throw new Error(`鏈上錨定的雜湊和平台帳本第 ${n} 筆不同，拒絕登記`);
    this.adopt({ address: att.attester });
    this.list().push({ seq: n, head: entry.hash, uid, tx: tx ?? null, block: block ?? null, at: nowIso() });
    await Audit.append("platform", "錨定上鏈", `第 ${n} 筆的鏈頭 ${entry.hash.slice(0, 10)}… → EAS`);
    Store.save();
    return this.list().at(-1);
  },
  // Each anchor against the chain, then against the local ledger as it is now
  async verify(rpcUrl) {
    const reader = EAS.reader(rpcUrl);
    const results = [];
    try {
      for (const a of this.list()) {
        let att;
        try {
          att = await reader.attestation(a.uid);
        } catch (err) {
          results.push({ ...a, status: "warn", detail: `讀不到鏈上資料（${err.shortMessage || err.message}）` });
          continue;
        }
        if (!att || att.schema !== easSchemaUid("anchor") || att.attester.toLowerCase() !== String(this.account()).toLowerCase()) {
          results.push({ ...a, status: "fail", detail: "鏈上找不到這筆錨定，或它不是平台的錨定帳戶寫的" });
          continue;
        }
        const [head, seq] = easDecode("anchor", att.data);
        const n = Number(seq), entry = Store.state.audit[n - 1];
        const chain = await Audit.verify(n);
        const base = { ...a, seq: n, time: att.time };
        if (!entry) results.push({ ...base, status: "fail", detail: `本地帳本少於 ${n} 筆：紀錄被刪掉了` });
        else if (!chain.ok) results.push({ ...base, status: "fail", detail: `本地帳本第 ${chain.brokenAt} 筆被改過（雜湊鏈斷掉）` });
        else if ("0x" + entry.hash !== head.toLowerCase()) results.push({ ...base, status: "fail", detail: `第 ${n} 筆的雜湊和鏈上錨定的不同：前面的紀錄被改過，而且整條鏈被重算過` });
        else results.push({ ...base, status: "pass", detail: `第 1–${n} 筆和鏈上錨定一致` });
      }
    } finally {
      reader.close?.();
    }
    return { results, ok: results.every((r) => r.status === "pass"), pending: this.pending() };
  },
};

/* ---------- KMS + signing service ---------- */
// Stand-in for an HSM: private keys are "sealed" as JWK in localStorage and unsealed as non-extractable CryptoKeys.
// A real deployment never stores private key material outside the HSM.
const KMS = {
  handles: new Map(), // verificationMethod id → CryptoKey (sign only)
  keysOf(orgId) { return Object.values(Store.state.kms).filter((k) => k.orgId === orgId); },
  activeKey(orgId) { return VcEngine.keys.custodial.active(this.keysOf(orgId)); },
  // Key records and their lifecycle come from the VC engine's custodial key service; the platform stores them
  async create(orgId) {
    const record = await VcEngine.keys.custodial.create(Store.org(orgId).did, this.keysOf(orgId));
    Store.state.kms[record.id] = { ...record, orgId };
    await this.unsealOne(Store.state.kms[record.id]);
    return Store.state.kms[record.id];
  },
  // Rotation: the engine retires the active key (it stays in did.json) and creates its successor
  async rotate(orgId) {
    const { old, key } = await VcEngine.keys.custodial.rotate(Store.org(orgId).did, this.keysOf(orgId));
    Store.state.kms[key.id] = { ...key, orgId };
    await this.unsealOne(Store.state.kms[key.id]);
    return { old, key: Store.state.kms[key.id] };
  },
  async unsealOne(k) {
    this.handles.set(k.id, await VcEngine.keys.custodial.unseal(k));
  },
  async unsealAll() {
    for (const k of Object.values(Store.state.kms)) if (k.state !== "revoked" && !this.handles.has(k.id)) await this.unsealOne(k);
  },
  signingKeys(orgId) {
    const org = Store.org(orgId), key = this.activeKey(orgId);
    if (!key) throw new Error(`${org.name} 沒有可用的簽章金鑰`);
    return VcEngine.keys.custodial.signer(org.did, key, this.handles.get(key.id));
  },
};

const Signer = {
  // Only the active key signs; the private key never leaves KMS (the engine gets a handle, not key bytes)
  async sign(orgId, unsigned, { challenge, domain } = {}) {
    const keys = KMS.signingKeys(orgId);
    const signed = await VcEngine.issuance.sign(unsigned, keys, { challenge, domain });
    await Audit.append(orgId, "簽章", `${credType(unsigned)}（#${fragmentOf(keys.verificationMethod)}）`);
    return signed;
  },
};

/* ---------- DID service: did:web documents, key rotation, key history ---------- */
const DidService = {
  url(org) { return DID_METHODS["did:web:"].parse(org.did).url; },
  // Retired keys stay listed so credentials they signed keep verifying; revoked keys disappear
  document(org) {
    const service = org.kind === "root" && Store.state.anchorAccount ? [{ id: `${org.did}#anchor-account`, type: "DppAnchorAccount",
      serviceEndpoint: `eip155:${ETHR.chainId}:${Store.state.anchorAccount}` }] : undefined;
    return VcEngine.keys.custodial.didDocument(org.did, KMS.keysOf(org.id), { service });
  },
  publish(org) { Hosting.put(this.url(org), this.document(org)); },
  publishAll() { for (const o of Object.values(Store.state.orgs)) this.publish(o); },
  async rotate(orgId) {
    const { old, key: k } = await KMS.rotate(orgId); // custodial lifecycle: active → retired, still listed in did.json
    this.publish(Store.org(orgId));
    await Audit.append(orgId, "金鑰輪替", `#${fragmentOf(old?.id ?? "")} 退役，#${fragmentOf(k.id)} 啟用`);
    Store.save();
    return k;
  },
  // Revoking a key removes it from did.json: everything it signed stops verifying (used after a key compromise)
  async revoke(keyId) {
    const k = Store.state.kms[keyId];
    const wasActive = VcEngine.keys.custodial.revoke(k);
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
    return (Store.state.statusLists[id] ??= { id, orgId, purpose, url: this.url(Store.org(orgId), purpose), set: [], used: [], vc: null, versions: [] });
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
  // Shared with the demo page (../js/status.js): index 0 is the left-most bit; GZIP, then multibase base64url ("u")
  encode: (set) => statusEncode(set, STATUS_BITS),
  decode: (encodedList) => statusDecode(encodedList),
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
    list.versions = [...(list.versions ?? []), list.vc].slice(-10); // older versions, for the rollback demo
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

/* ---------- StatusLedger: status list versions anchored on Sepolia (EAS), against rollback and split views ---------- */
// A status list is a live document the platform serves. Its signature proves who wrote a version, not that it is the
// latest one: a host could hand a verifier last week's list (before a revocation) or different lists to different
// verifiers. Each version's digest is attested on chain (many lists in one transaction), and verification compares
// the list it was given with the newest anchored version for that URL.
const StatusLedger = {
  digest: async (listVc) => "0x" + toHex(await sha256(jcs(listVc))),
  anchored() { return (Store.state.listAnchors ??= {}); }, // url → [{ digest, uid, tx, block, at }], oldest first
  async pending() {
    const out = [];
    for (const list of Object.values(Store.state.statusLists)) {
      if (!list.vc) continue;
      const digest = await this.digest(list.vc);
      if (this.anchored()[list.url]?.at(-1)?.digest !== digest) out.push({ list, digest });
    }
    return out;
  },
  async anchor(wallet) {
    Anchor.claim(wallet);
    const pending = await this.pending();
    if (!pending.length) throw new Error("所有狀態清單都已錨定到最新版本");
    const reader = EAS.reader();
    try { await easEnsureSchema(wallet, "statusList", reader); } finally { reader.close?.(); }
    const res = await easMultiAttest(wallet, "statusList", pending.map((p) => [p.list.url, p.digest]));
    Anchor.adopt(wallet);
    pending.forEach((p, i) => (this.anchored()[p.list.url] ??= []).push({ digest: p.digest, uid: res.uids[i], tx: res.hash, block: res.block, at: nowIso() }));
    this.cache = null;
    await Audit.append("platform", "狀態清單錨定", `${pending.length} 份清單 → EAS（一筆交易）`);
    Store.save();
    return pending.length;
  },
  /* Server mode: the browser wallet attested several lists in one transaction; check each attestation on chain:
     status list schema, by the anchoring account, and a digest that matches a version this platform published */
  async accept(uids, { tx, block } = {}) {
    if (!Array.isArray(uids) || !uids.length) throw new Error("需要 attestation uid 清單");
    const accepted = [];
    for (const uid of uids) {
      if (Object.values(this.anchored()).flat().some((a) => a.uid === uid)) throw new Error(`attestation ${uid.slice(0, 10)}… 已經登記過`);
      const att = await readAttestation(uid);
      if (att.schema !== easSchemaUid("statusList")) throw new Error("這筆 attestation 不是狀態清單錨定的 schema");
      const acct = Anchor.account();
      if (acct && acct.toLowerCase() !== att.attester.toLowerCase()) throw new Error(`錨定帳戶是 ${acct}，這筆是 ${att.attester} 寫的`);
      const [url, digest] = easDecode("statusList", att.data);
      const list = Object.values(Store.state.statusLists).find((l) => l.url === url);
      if (!list) throw new Error(`平台沒有這份狀態清單：${url}`);
      const versions = [...(list.versions ?? []), list.vc].filter(Boolean);
      let known = false;
      for (const v of versions) if ((await this.digest(v)) === digest.toLowerCase()) known = true;
      if (!known) throw new Error(`錨定的雜湊不是平台發布過的任何一版 ${url}`);
      Anchor.adopt({ address: att.attester });
      accepted.push({ url, entry: { digest: digest.toLowerCase(), uid, tx: tx ?? null, block: block ?? null, at: nowIso() } });
    }
    for (const a of accepted) (this.anchored()[a.url] ??= []).push(a.entry);
    this.cache = null;
    await Audit.append("platform", "狀態清單錨定", `${accepted.length} 份清單 → EAS（一筆交易）`);
    Store.save();
    return accepted.length;
  },
  cache: null,           // { at, account, byUrl: Map(url → [{ digest, time, uid }]) } read from the chain, kept 20 s
  seen: new Map(),       // attestation uid → attestation (they never change: the schema is not revocable)
  async onChain(account, rpcUrl) {
    if (this.cache && this.cache.account === account && Date.now() - this.cache.at < 20000) return this.cache.byUrl;
    const reader = EAS.reader(rpcUrl);
    try {
      const byUrl = new Map();
      for (const log of await reader.attested(account, easSchemaUid("statusList"), EAS.searchFrom)) {
        if (!this.seen.has(log.uid)) this.seen.set(log.uid, await reader.attestation(log.uid));
        const a = this.seen.get(log.uid);
        if (!a || a.attester.toLowerCase() !== account.toLowerCase()) continue;
        const [url, digest] = easDecode("statusList", a.data);
        if (!byUrl.has(url)) byUrl.set(url, []);
        byUrl.get(url).push({ digest: digest.toLowerCase(), time: a.time, uid: log.uid });
      }
      this.cache = { at: Date.now(), account, byUrl };
      return byUrl;
    } finally {
      reader.close?.();
    }
  },
  /* { status, detail } for one status list credential, or null when the platform publishes no anchoring account */
  async check(listVc, rpcUrl) {
    const account = Anchor.publishedAccount();
    if (!account) return null;
    let byUrl;
    try {
      byUrl = await this.onChain(account, rpcUrl);
    } catch (err) {
      return { status: "warn", detail: `讀不到鏈上錨定（${err.shortMessage || err.message}），無法確認清單沒被掉包` };
    }
    const versions = byUrl.get(listVc.id) ?? [];
    if (!versions.length) return { status: "warn", detail: "這份狀態清單還沒錨定上鏈" };
    const digest = await this.digest(listVc), latest = versions.at(-1);
    const when = (v) => new Date(v.time * 1000).toLocaleString();
    if (latest.digest === digest) return { status: "pass", detail: `與鏈上最新錨定一致（${when(latest)}）` };
    if (versions.some((v) => v.digest === digest)) {
      return { status: "fail", detail: `拿到的是舊版狀態清單，鏈上已有更新的版本（${when(latest)}）：可能是回滾攻擊` };
    }
    if (Date.parse(listVc.validFrom) / 1000 > latest.time) return { status: "warn", detail: "清單在最後一次錨定之後更新過，還沒錨定" };
    return { status: "fail", detail: "這份狀態清單和鏈上錨定的任何版本都不同：可能被掉包" };
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
  // GS1 rules live in the DPP engine
  checkDigit: (body13) => DppEngine.gs1.checkDigit(body13),
  gtin14: (input) => DppEngine.gs1.gtin14(input),
  upi(orgId, gtin, serial) { return DppEngine.gs1.link(Store.org(orgId).resolver, { gtin, serial }); },
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
const TIERS = DppEngine.tiers;
const CATEGORY_TEMPLATES = DppEngine.categories; // product groups and their fields (ESPR-style information requirements)

const Passports = {
  create(upi) {
    const item = Store.state.items[upi], model = Store.state.models[item.gtin];
    const id = "pp-" + crypto.randomUUID().slice(0, 8);
    const attrs = DppEngine.template(model.category);
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
  certLink: (vc) => VcEngine.digestSRI(vc),
  async publish(id) {
    const p = Store.state.passports[id];
    const item = Store.state.items[p.upi], model = Store.state.models[item.gtin], org = Store.org(model.orgId);
    const check = DppEngine.validate(model.category, p.draft.attributes);
    if (!check.ok) throw new Error(check.problems.join("；"));
    const reg = await Registry.register(p.upi, org.id);
    const version = p.versions.length + 1;
    const bundle = await DppEngine.buildPassport({
      product: { upi: p.upi, gtin: item.gtin, serial: item.serial, name: model.name, category: model.category,
        manufacturer: { id: org.did, name: org.name }, facility: item.facility, madeOn: item.madeOn },
      attributes: p.draft.attributes,
      issuer: org.did,
      version,
      registrationId: reg.registrationId,
      certificates: p.draft.certIds.map((cid) => Store.state.credentials[cid]?.vc).filter(Boolean),
      status: () => StatusService.allocate(org.id, "revocation"),
    });
    const signed = await DppEngine.signPassport(bundle, (doc) => Signer.sign(org.id, doc));
    const vc = signed.passport;
    Issuance.record(vc, "passport", org.id, null, { upi: p.upi });
    // Restricted tiers are separate credentials, released only after the policy decision allows it
    const sections = {};
    for (const [tier, s] of Object.entries(signed.sections)) {
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
        else if (status === "pass") detail = res.detail;
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
    // Before trusting its bits: is this the version anchored on chain? (null = the platform anchors nothing)
    const ledger = await StatusLedger.check(listVc);
    if (ledger?.status === "fail") return ledger;
    const bits = await StatusService.decode(listVc.credentialSubject.encodedList);
    const i = Number(e.statusListIndex);
    const on = (bits[i >> 3] & (0x80 >> (i & 7))) !== 0;
    if (on) return { status: "fail", detail: e.statusPurpose === "suspension" ? "已被發證者暫停" : "已被發證者撤銷" };
    if (ledger?.status === "warn") return { status: "warn", detail: "狀態清單查詢：有效，但" + ledger.detail };
    return { status: "pass", detail: "狀態清單查詢：有效" + (ledger ? `（${ledger.detail}）` : "") };
  },
};

/* ---------- Authorised access: OID4VP-style exchange + policy decision point ---------- */
const POLICY = DppEngine.policy; // roles public / partner / government and the tiers each may read

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
    let role = "public";
    for (const vc of vp.verifiableCredential) {
      const res = await Verify.credential(vc);
      const ok = res.verdict !== "invalid";
      steps.push({ label: `資格憑證 ${credType(vc)}`, ok, detail: ok ? `發證者可信、狀態有效（${Store.orgByDid(vc.issuer)?.name}）` : res.checks.find((c) => c.status === "fail").detail });
      if (ok && POLICY.roles[credType(vc)]) role = POLICY.roles[credType(vc)];
    }
    const tiers = POLICY.tiers[role];
    steps.push({ label: "授權決策（PDP）", ok: role !== "public", detail: `角色：${POLICY.names[role]}；可讀：${tiers.map((t) => TIERS[t]).join("、")}` });
    if (role === "public") return { ok: false, steps, errors: ["AccessDenied"] };
    const p = Passports.ofItem(upi), v = Passports.latest(p);
    const sections = tiers.filter((t) => v?.sections?.[t]).map((t) => Store.state.credentials[v.sections[t]].vc);
    await Audit.append(Store.orgByDid(vp.holder)?.id ?? vp.holder, "讀取受限欄位", `${upi}（${tiers.filter((t) => t !== "public").join("、")}）`);
    Store.save();
    return { ok: true, steps, role, sections };
  },
};

/* ---------- Event notifications (the architecture's Webhook layer): engine events, logged per platform ---------- */
const Events = {
  max: 200,
  log() { return (Store.state.events ??= []); },
  record(event) {
    if (!Store.state) return;
    const log = this.log();
    log.push(event);
    if (log.length > this.max) log.splice(0, log.length - this.max);
  },
};
VcEngine.events.on((event) => Events.record(event));

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
