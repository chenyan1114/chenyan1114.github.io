/* VC engine: the "核心 VC 憑證服務" layer of the reference architecture (NTU, VC 服務大平台), without any DOM.
   Four engines, as in the diagram, on top of the building blocks (it adds no cryptography of its own):
     issuance      憑證發行引擎      build VC 2.0 documents, pick their credentialStatus, sign (VCs and VPs)
     verification  憑證驗證引擎      structure + signature + status in one report with a verdict; VPs; challenges
     status        吊銷與狀態管理    W3C Bitstring Status List (successor of Status List 2021), or history on chain
     keys          代管金鑰與身分    DIDs, and a custodial key lifecycle (create, rotate, revoke, did.json)
   plus events (the diagram's Webhook 事件通知): every engine emits what happened, subscribers get it.
   Building blocks: vc.js · did-key.js / did-web.js / did-ethr.js · status.js · vc-ledger.js / eas.js · vp.js.
   Used by ui.js (cards 2–4), dpp-engine.js (card 6) and platform/. Load it after all of those files.
   The flat names (VcEngine.sign, VcEngine.verify, …) are kept as shortcuts to the engines below. */
"use strict";

const VC_V2 = "https://www.w3.org/ns/credentials/v2";

const VcEngine = {
  version: "1.1",

  /* ---------- events (Webhook 事件通知) ---------- */
  events: {
    listeners: new Set(),
    on(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); },
    emit(type, data) {
      const event = { ...data, type, at: new Date().toISOString() };
      for (const fn of this.listeners) {
        try { fn(event); } catch (e) { console.warn("事件訂閱者出錯：", e); }
      }
    },
  },

  /* ---------- 代管金鑰與身分 (DID / custodial key lifecycle) ---------- */
  keys: {
    methods: () => Object.entries(DID_METHODS).map(([prefix, m]) => ({ prefix, name: m.name })),
    generate(prefix, opts) {
      const m = DID_METHODS[prefix];
      if (!m) throw new Error(`不支援的 DID 方法：${prefix}`);
      return m.generate(opts);
    },
    resolve: (did, opts) => didMethodOf(did).resolve(did, opts),
    /* Keys an operator holds for its tenants. Records are plain JSON the caller stores; `sealed` stands in for an
       HSM-wrapped private key (a real deployment keeps it inside the HSM / cloud KMS and never sees the bytes).
       Unsealing gives a non-extractable CryptoKey handle that can sign but not be exported.
       Lifecycle: active → retired (rotation: stays in did.json, old signatures keep verifying)
                         → revoked (compromise: removed from did.json, everything it signed stops verifying) */
    custodial: {
      async create(did, existing = []) {
        const { privateKey, pub } = await generateEd25519(true);
        const jwk = await crypto.subtle.exportKey("jwk", privateKey);
        const record = { id: `${did}#key-${existing.length + 1}`, alg: "Ed25519", publicKeyMultibase: ed25519Multibase(pub), state: "active",
          createdAt: new Date().toISOString(), sealed: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d } };
        VcEngine.events.emit("key.created", { did, keyId: record.id });
        return record;
      },
      unseal: (record) => crypto.subtle.importKey("jwk", { ...record.sealed }, { name: "Ed25519" }, false, ["sign"]),
      active: (records) => records.find((k) => k.state === "active"),
      /* Retire the active key and create its successor */
      async rotate(did, records) {
        const old = this.active(records);
        if (old) old.state = "retired";
        const key = await this.create(did, records);
        VcEngine.events.emit("key.rotated", { did, retired: old?.id, active: key.id });
        return { old, key };
      },
      /* Revoke one key; true when it was the active one (the caller then needs a new key) */
      revoke(record) {
        const wasActive = record.state === "active";
        record.state = "revoked";
        delete record.sealed;
        VcEngine.events.emit("key.revoked", { keyId: record.id });
        return wasActive;
      },
      /* What VcEngine.sign needs: the DID, the suite, the key handle and its verificationMethod id */
      signer: (did, record, handle) => ({ did, cryptosuite: "eddsa-jcs-2022", privateKey: handle, verificationMethod: record.id }),
      /* did:web document for a key ring: retired keys stay listed, revoked keys disappear */
      didDocument(did, records, { service } = {}) {
        const keys = records.filter((k) => k.state !== "revoked");
        const ids = keys.map((k) => k.id);
        return {
          "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
          id: did,
          verificationMethod: keys.map((k) => ({ id: k.id, type: "Multikey", controller: did, publicKeyMultibase: k.publicKeyMultibase })),
          authentication: ids,
          assertionMethod: ids,
          ...(service?.length && { service }),
        };
      },
    },
  },

  /* ---------- 憑證發行引擎 (issuance) ---------- */
  issuance: {
    /* Formats this engine issues in the browser. SD-JWT VC (dc+sd-jwt) is issued by the EUDI backend
       (server/issuer.mjs, @sd-jwt/sd-jwt-vc) through OpenID4VCI, not here. */
    formats: { "vc+di": "W3C VC 2.0 + Data Integrity（eddsa-jcs-2022、ecdsa-secp256k1-recovery-jcs-demo）" },
    /* A generic unsigned VC 2.0. type: the credential's own type(s); subject: credentialSubject (object or array) */
    credential({ type, issuer, subject, id = "urn:uuid:" + crypto.randomUUID(), validFrom = new Date().toISOString(),
      validUntil, status, related, context = [] } = {}) {
      if (!issuer) throw new Error("credential 需要 issuer");
      if (!subject) throw new Error("credential 需要 credentialSubject");
      const toDateTime = (d) => (/^\d{4}-\d{2}-\d{2}$/.test(d) ? d + "T00:00:00Z" : d);
      return {
        "@context": [VC_V2, ...context],
        id,
        type: ["VerifiableCredential", ...[].concat(type ?? [])],
        issuer,
        ...(validFrom && { validFrom: toDateTime(validFrom) }),
        ...(validUntil && { validUntil: toDateTime(validUntil) }),
        credentialSubject: subject,
        ...(related?.length && { relatedResource: related }),
        ...(status && { credentialStatus: status }),
      };
    },
    isoCertificate: (form, issuerDid, holderDid) => buildVc(form, issuerDid, holderDid),
    /* The credentialStatus a new VC from this issuer should carry, or undefined. A MetaMask did:ethr issuer
       records history on chain (ERC-1056 events or EAS); a did:web issuer uses status lists on its domain. */
    async statusFor(keys, { ledger = "erc1056", blockNumber } = {}) {
      if (keys?.viaWallet) return ledger === "eas" ? easStatusEntry(keys.did, await blockNumber?.()) : ledgerStatusEntry(keys.did);
      if (String(keys?.did).startsWith("did:web:")) return statusEntries(keys.did);
      return undefined;
    },
    /* A VC is signed by its issuer (assertionMethod), a VP by its holder (authentication + optional challenge/domain) */
    async sign(doc, keys, { challenge, domain } = {}) {
      if (!isPlainObject(doc)) throw new Error("要簽的不是 JSON 物件");
      if (doc.proof !== undefined) throw new Error("這份文件已經有 proof（本 demo 只支援單一 proof）");
      const isVp = [].concat(doc.type).includes("VerifiablePresentation");
      const signerDid = isVp ? doc.holder : (typeof doc.issuer === "string" ? doc.issuer : doc.issuer?.id);
      if (!keys || keys.did !== signerDid) {
        throw new Error(isVp ? "持有人私鑰與 VP 的 holder 不符" : "這份 VC 的 issuer 不是這把私鑰的 DID（私鑰 = 簽發能力）");
      }
      if (keys.viaWallet && !keys.verificationMethod) throw new Error("請先在第 2 卡 🔗 授權簽名金鑰。");
      const options = isVp ? { proofPurpose: "authentication", challenge, domain } : undefined;
      const signed = { ...doc, proof: await createProof(doc, keys, undefined, options) };
      VcEngine.events.emit(isVp ? "presentation.signed" : "credential.issued",
        { id: doc.id, credentialType: [].concat(doc.type).at(-1), signer: signerDid, verificationMethod: signed.proof.verificationMethod });
      return signed;
    },
    present: (vcs, holderKeys, request) => VcEngine.issuance.sign(buildVp(holderKeys?.did, vcs), holderKeys, request ?? {}),
    /* relatedResource entry: id + SRI digest of the JCS form, so swapping the linked VC is detected */
    async digestSRI(vc) {
      const digest = btoa(String.fromCharCode(...(await sha256(jcs(vc)))));
      return { id: vc.id, mediaType: "application/vc", digestSRI: "sha256-" + digest };
    },
    pack: (vc) => packVc(vc),
  },

  /* ---------- 憑證驗證引擎 (verification) ---------- */
  verification: {
    /* Everything a verifier asks about one VC. form (optional): the issuer page's own form/DIDs, mismatches are ⚠.
       profile: "iso" (this demo's certificate expectations), "generic" (VC 2.0 rules only) or "auto" (iso for an
       IsoCertificationCredential or when a form is given). Returns report() fields with [簽名] / [狀態] tags, plus
       verdict: valid | warning | invalid */
    async verify(vc, { rpcUrl, form, status = true, profile = "auto" } = {}) {
      if (profile === "auto") profile = form || [].concat(vc?.type ?? []).includes("IsoCertificationCredential") ? "iso" : "generic";
      const r = verifyVc(vc, form, { profile });
      if (isPlainObject(vc) && vc.proof !== undefined) {
        const steps = [["簽名", () => verifyProof(vc, { rpcUrl })]];
        if (status) steps.push(["狀態", () => verifyStatus(vc, { rpcUrl })]);
        for (const [tag, check] of steps) {
          try {
            const pr = await check();
            for (const k of ["passes", "warns", "fails", "infos"]) r[k].push(...pr[k].map((t) => `[${tag}] ${t}`));
          } catch (e) {
            r.fails.push(`[${tag}] 驗證過程出錯：` + e.message);
          }
        }
      }
      r.verdict = r.fails.length ? "invalid" : r.warns.length ? "warning" : "valid";
      VcEngine.events.emit("credential.verified", { id: vc?.id, verdict: r.verdict });
      return r;
    },
    /* Phase 1 (static VP). For phase 2 (challenge + audience) use verifier(). */
    verifyPresentation: (vp, opts) => verifyVp(vp, opts),
    /* A verifier that issues single-use, expiring challenges bound to its own id (vp.js) */
    verifier: (id, opts) => new Verifier(id, opts),
    unpack: (packed) => unpackVc(packed),
  },

  /* ---------- 吊銷與狀態管理 (revocation and suspension) ---------- */
  status: {
    /* Which mechanism a VC uses: "bitstring" (W3C list on the issuer's site), "erc1056" / "eas" (on chain), or null */
    kind(vc) {
      const types = [].concat(vc?.credentialStatus ?? []).map((e) => e?.type);
      if (types.includes("BitstringStatusListEntry")) return "bitstring";
      if (types.includes(LEDGER.statusType)) return "erc1056";
      if (types.includes(EAS.statusType)) return "eas";
      return null;
    },
    encode: (indices, length) => statusEncode(indices, length),
    decode: (encodedList) => statusDecode(encodedList),
    /* Status lists: sign a new list version with the issuer key (published separately). action: revoke | suspend | reinstate */
    async change(vc, keys, action) {
      const [purpose, on] = { revoke: ["revocation", true], suspend: ["suspension", true], reinstate: ["suspension", false] }[action] ?? [];
      if (!purpose) throw new Error("未知的動作：" + action);
      if (this.kind(vc) !== "bitstring") throw new Error("這張 VC 沒有狀態清單欄位");
      const list = await updateStatus(keys, vc, purpose, on);
      VcEngine.events.emit("status.changed", { id: vc.id, action, list: list.id });
      return list;
    },
    /* On-chain history: the VC's current state, same shape for both backends ({ issued, suspended, revoked, history }) */
    async onChain(vc, { rpcUrl } = {}) {
      const kind = this.kind(vc);
      const address = DID_METHODS["did:ethr:"].parse(vc.issuer).address;
      if (kind === "erc1056") return vcLedgerState(await LEDGER.read(address, rpcUrl), vcStatusKey(vc));
      if (kind === "eas") {
        const reader = EAS.reader(rpcUrl);
        try {
          const entry = [].concat(vc.credentialStatus).find((e) => e.type === EAS.statusType);
          return await easVcState(reader, address, vc, entry.fromBlock);
        } finally {
          reader.close?.();
        }
      }
      throw new Error("這張 VC 沒有鏈上狀態欄位");
    },
    /* Write one event with the issuer's wallet (issued | suspended | reinstated | revoked). Reads the state first and
       refuses pointless transactions; registers a missing EAS schema first (onStep tells the page what's happening) */
    async record(vc, wallet, action, { rpcUrl, onStep = () => {} } = {}) {
      if (!wallet || wallet.did !== vc.issuer) throw new Error("只有發證帳戶本人能寫入：請用這張 VC 的 issuer 帳戶連接 MetaMask。");
      const st = await this.onChain(vc, { rpcUrl });
      const refusal = ledgerRefusal(st, action);
      if (refusal) throw Object.assign(new Error(refusal), { refused: true });
      let res;
      if (this.kind(vc) === "erc1056") {
        res = await recordVcEvent(wallet, action, vc);
      } else {
        const schema = action === "suspended" ? "suspension" : action === "issued" ? "vc" : null;
        if (schema) {
          const reader = EAS.reader(rpcUrl);
          try {
            if (!(await reader.schemaExists(easSchemaUid(schema)))) {
              onStep(`第一次使用：先註冊 EAS schema「${EAS.schemas[schema].label}」（只需一次，之後大家共用），請在 MetaMask 確認…`);
              await easEnsureSchema(wallet, schema, reader);
              onStep("schema 已註冊。請再確認一筆交易，把紀錄寫上鏈…");
            }
          } finally {
            reader.close?.();
          }
        }
        res = await easRecordVcEvent(wallet, action, vc, st);
      }
      VcEngine.events.emit("status.recorded", { id: vc.id, action, tx: res.hash });
      return res;
    },
  },
};

/* Shortcuts used across the pages */
Object.assign(VcEngine, {
  methods: VcEngine.keys.methods,
  generate: (prefix, opts) => VcEngine.keys.generate(prefix, opts),
  resolve: VcEngine.keys.resolve,
  credential: (opts) => VcEngine.issuance.credential(opts),
  isoCertificate: VcEngine.issuance.isoCertificate,
  statusFor: (keys, opts) => VcEngine.issuance.statusFor(keys, opts),
  sign: (doc, keys, opts) => VcEngine.issuance.sign(doc, keys, opts),
  present: VcEngine.issuance.present,
  digestSRI: (vc) => VcEngine.issuance.digestSRI(vc),
  pack: VcEngine.issuance.pack,
  verify: (vc, opts) => VcEngine.verification.verify(vc, opts),
  verifyPresentation: VcEngine.verification.verifyPresentation,
  unpack: VcEngine.verification.unpack,
});
