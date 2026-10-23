/* did:web: the DID names an HTTPS location where its DID document is published, which ties the issuer to a domain.
     did:web:example.com              → https://example.com/.well-known/did.json
     did:web:example.com:issuers:acme → https://example.com/issuers/acme/did.json   (a port is written as %3A)
   Keys are Ed25519 (WebCrypto) and signatures use the shared eddsa-jcs-2022 suite in vc.js.
   Resolution uses the official web-did-resolver. A document generated in this page but not published yet
   stands in locally, with a warning, so the flow can be tried before hosting did.json anywhere. */
"use strict";

const WEB = {
  // Versions must match package.json devDependencies (checked by test/test.js)
  resolverModules: [
    "https://cdn.jsdelivr.net/npm/did-resolver@5.0.1/+esm",
    "https://cdn.jsdelivr.net/npm/web-did-resolver@3.2.0/+esm",
  ],
  importResolver: () => Promise.all(WEB.resolverModules.map((u) => import(u))), // test/test.js swaps in the npm copies
  fetch: null,          // test/test.js injects a fake fetch to simulate hosting
  localDocs: new Map(), // DID → document generated in this page (may not be published yet)
};

let webResolver = null;

async function resolveDidWeb(did) {
  if (!webResolver) {
    const [{ Resolver }, { getResolver }] = await WEB.importResolver();
    const fetchFn = (...args) => (WEB.fetch ?? globalThis.fetch)(...args);
    webResolver = new Resolver(getResolver({ fetch: fetchFn }));
  }
  return webResolver.resolve(did);
}

/* Domain input ("example.com/issuers/acme", optionally with https:// or a port) → did:web DID */
function didWebFromDomain(domain) {
  const cleaned = String(domain ?? "").trim().replace(/^https?:\/\//i, "").replace(/\/+$/, "");
  if (!cleaned) throw new Error("請先填 did:web 網域");
  const [host, ...path] = cleaned.split("/");
  return "did:web:" + [host.toLowerCase(), ...path].filter(Boolean).map(encodeURIComponent).join(":");
}

/* Issuer key object plus the DID document to publish as did.json (one Ed25519 key, #key-1) */
function webIssuerKeys(did, privateKey, pub) {
  const vmId = did + "#key-1";
  const didDocument = {
    "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
    id: did,
    verificationMethod: [{ id: vmId, type: "Multikey", controller: did, publicKeyMultibase: ed25519Multibase(pub) }],
    authentication: [vmId],
    assertionMethod: [vmId],
  };
  WEB.localDocs.set(did, didDocument);
  return { did, cryptosuite: "eddsa-jcs-2022", privateKey, verificationMethod: vmId, didDocument };
}

/* verificationMethod entry → 32-byte Ed25519 public key, for the key formats seen in published did:web documents */
function ed25519FromMethod(m) {
  if (typeof m.publicKeyMultibase === "string") return ed25519FromMultibase(m.publicKeyMultibase); // Multikey / Ed25519VerificationKey2020
  if (m.publicKeyJwk?.kty === "OKP" && m.publicKeyJwk.crv === "Ed25519") return base64urlDecode(m.publicKeyJwk.x); // JsonWebKey2020
  if (m.type === "Ed25519VerificationKey2018" && typeof m.publicKeyBase58 === "string") {     // legacy raw key
    return base58btcDecode(m.publicKeyBase58);
  }
  const jwkInfo = m.publicKeyJwk ? `，${m.publicKeyJwk.kty}/${m.publicKeyJwk.crv}` : "";
  throw new Error(`不支援的金鑰（${m.type}${jwkInfo}），本 demo 只驗 Ed25519`);
}

DID_METHODS["did:web:"] = {
  name: "did:web（網域）",
  holder: "did:key:", // the holder is usually another party without a website, so it gets a did:key

  async generate({ domain } = {}) {
    const did = didWebFromDomain(domain);
    this.parse(did);
    const { privateKey, pub } = await generateEd25519(true); // exportable, so the key can sign again after a reload
    return webIssuerKeys(did, privateKey, pub);
  },

  /* Key file = the private key for a published did.json; it must stay with its owner and never go into a repo */
  async exportKeyFile(keys) {
    const jwk = await crypto.subtle.exportKey("jwk", keys.privateKey);
    return {
      note: "did:web 簽名私鑰：只能自己保存，不可上傳到 GitHub 或分享給別人",
      did: keys.did,
      verificationMethod: keys.verificationMethod,
      privateKeyJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d },
    };
  },

  async importKeyFile(file) {
    const jwk = file?.privateKeyJwk;
    if (!file?.did || jwk?.kty !== "OKP" || jwk.crv !== "Ed25519" || !jwk.d || !jwk.x) {
      throw new Error("不是本頁匯出的 did:web 私鑰檔");
    }
    this.parse(file.did);
    const privateKey = await crypto.subtle.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: jwk.x, d: jwk.d }, ED25519, false, ["sign"]);
    return webIssuerKeys(file.did, privateKey, base64urlDecode(jwk.x));
  },

  /* Compare the key this page holds with what the website publishes: "same" | "different" | "unpublished" */
  async publishedStatus(keys) {
    let res;
    try { res = await resolveDidWeb(keys.did); } catch { return "unpublished"; }
    if (res.didResolutionMetadata?.error) return "unpublished";
    const mine = keys.didDocument.verificationMethod[0].publicKeyMultibase;
    const theirs = (res.didDocument.verificationMethod ?? []).find((v) => fragmentOf(v.id) === fragmentOf(keys.verificationMethod));
    try { return theirs && ed25519Multibase(ed25519FromMethod(theirs)) === mine ? "same" : "different"; } catch { return "different"; }
  },

  parse(did) {
    const m = /^did:web:([^:#?/]+)((?::[^:#?/]+)*)$/.exec(did);
    if (!m) throw new Error("格式應為 did:web:<網域>[:路徑]");
    const host = decodeURIComponent(m[1]);
    let u;
    try { u = new URL(`https://${host}`); } catch { throw new Error("網域不合法：" + host); }
    if (u.pathname !== "/" || u.username || u.search || u.hash) throw new Error("網域不合法：" + host);
    const path = m[2] ? m[2].slice(1).split(":").map(decodeURIComponent).join("/") + "/did.json" : ".well-known/did.json";
    return { host, url: `https://${host}/${path}` };
  },

  describe: ({ url }) => `did:web 格式正確（DID 文件在 ${url}）`,

  defaultFragment: () => "key-1",

  /* Fetch the published DID document; fall back to this page's unpublished copy with a warning */
  async resolve(did) {
    const { url } = this.parse(did);
    let res;
    try {
      res = await resolveDidWeb(did);
    } catch (e) {
      res = { didDocument: null, didDocumentMetadata: {}, didResolutionMetadata: { error: "resolutionError", message: e.message } };
    }
    const err = res.didResolutionMetadata?.error;
    if (err && WEB.localDocs.has(did)) {
      return {
        didDocument: WEB.localDocs.get(did),
        didDocumentMetadata: {},
        didResolutionMetadata: { localOnly: true, url, networkError: `${err}：${res.didResolutionMetadata.message ?? ""}` },
      };
    }
    return res;
  },

  async ed25519Key(r, { did, didInfo, fragment, purpose }) {
    const res = await this.resolve(did);
    const meta = res.didResolutionMetadata ?? {};
    if (meta.error) {
      r.fails.push(`無法從 ${didInfo.url} 取得 DID 文件：${meta.message ?? meta.error}`);
      return null;
    }
    if (meta.localOnly) {
      r.warns.push(`did.json 尚未放上 ${didInfo.url}（${meta.networkError}），改用本頁暫存的 DID 文件模擬；其他人驗證會失敗`);
    } else {
      r.passes.push(`已從 ${didInfo.url} 取得 DID 文件`);
    }
    const doc = res.didDocument;
    const m = (doc.verificationMethod ?? []).find((v) => fragmentOf(v.id) === fragment);
    if (!r.check(!!m, `DID 文件中有 #${fragment}（${m?.type}）`, `DID 文件裡沒有 #${fragment}（金鑰不存在或已被移除）`)) return null;
    if (!checkRelationship(r, doc, fragment, purpose)) return null;
    try {
      return ed25519FromMethod(m);
    } catch (e) {
      r.fails.push(e.message);
      return null;
    }
  },
};
