/* Shared core (no DOM): encoding, JCS, verification reports, the generic Data Integrity flow,
   VC assembly and structural checks. did-key.js / did-ethr.js register into DID_METHODS / SUITES. */
"use strict";

const DID_METHODS = {}; // DID prefix → { name, generate(opts), parse(did), describe(info), resolve(did, opts) }
const SUITES = {};      // cryptosuite name → { sigLen, fragment(did), note, sign(keys, hashData), verify(r, ctx) }

/* ---------- Encoding ---------- */
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function base58btcEncode(bytes) {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  for (; n > 0n; n /= 58n) out = B58[Number(n % 58n)] + out;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) out = "1" + out;
  return out;
}

function base58btcDecode(str) {
  let n = 0n;
  for (const ch of str) {
    const i = B58.indexOf(ch);
    if (i < 0) throw new Error("base58 非法字元: " + ch);
    n = n * 58n + BigInt(i);
  }
  const tail = [];
  for (; n > 0n; n >>= 8n) tail.unshift(Number(n & 0xffn));
  const zeros = str.match(/^1*/)[0].length;
  return Uint8Array.from([...new Array(zeros).fill(0), ...tail]);
}

function concatBytes(...arrs) {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let p = 0;
  for (const a of arrs) { out.set(a, p); p += a.length; }
  return out;
}

const base64urlEncode = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const base64urlDecode = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

/* Share a VC inside a URL fragment (#vc=…): JSON → deflate (built-in CompressionStream) → base64url.
   The fragment never reaches the web server. Key order doesn't matter because signatures are over JCS. */
async function packVc(vc) {
  const stream = new Blob([JSON.stringify(vc)]).stream().pipeThrough(new CompressionStream("deflate"));
  return base64urlEncode(new Uint8Array(await new Response(stream).arrayBuffer()));
}

async function unpackVc(packed) {
  try {
    const stream = new Blob([base64urlDecode(packed)]).stream().pipeThrough(new DecompressionStream("deflate"));
    return JSON.parse(await new Response(stream).text());
  } catch {
    // decompression errors surface as a misleading "Failed to fetch" in browsers
    throw new Error("連結內容不完整或被改過，無法還原成證書");
  }
}

async function sha256(data) {
  if (typeof data === "string") data = new TextEncoder().encode(data);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

/* ---------- JCS (RFC 8785): strings and numbers serialize exactly as JSON.stringify does; only key order is ours ---------- */
function jcs(v) {
  if (Array.isArray(v)) return "[" + v.map(jcs).join(",") + "]";
  if (v !== null && typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => jcs(k) + ":" + jcs(v[k])).join(",") + "}";
  }
  if (typeof v === "string" && !v.isWellFormed()) throw new Error("JCS 不允許孤立 surrogate");
  if (typeof v === "number" && !Number.isFinite(v)) throw new Error("JCS 不允許 NaN/Infinity");
  const s = JSON.stringify(v);
  if (s === undefined) throw new Error("JCS 不允許 undefined/function/symbol");
  return s;
}

/* ---------- Verification report: only fails make verification fail; warns are informational ---------- */
function report() {
  const r = { fails: [], warns: [], passes: [], infos: [] };
  r.check = (ok, pass, fail) => { (ok ? r.passes : r.fails).push(ok ? pass : fail); return ok; };
  r.soft = (ok, pass, warn) => { (ok ? r.passes : r.warns).push(ok ? pass : warn); return ok; };
  return r;
}

const isPlainObject = (x) => x !== null && typeof x === "object" && !Array.isArray(x);
const isDateTime = (x) => typeof x === "string" && !isNaN(Date.parse(x));

function didMethodOf(did) {
  const prefix = Object.keys(DID_METHODS).find((p) => typeof did === "string" && did.startsWith(p));
  if (!prefix) throw new Error("不支援的 DID method（只支援 " + Object.keys(DID_METHODS).join("、") + "）");
  return DID_METHODS[prefix];
}

// "did:x:y#key-1", "#key-1" (relative refs are allowed in DID documents) → "key-1"
const fragmentOf = (id) => String(id).slice(String(id).indexOf("#") + 1);

/* ---------- Data Integrity flow shared by every cryptosuite ---------- */
// hashData = SHA256(JCS(proof options)) ‖ SHA256(JCS(unsigned document)), proof options first
async function diHashData(proofOptions, doc) {
  return concatBytes(await sha256(jcs(proofOptions)), await sha256(jcs(doc)));
}

async function createProof(unsignedVc, keys, created = new Date().toISOString()) {
  const suite = SUITES[keys.cryptosuite];
  if (!suite) throw new Error("缺少 issuer 私鑰材料，請重新生成 DID");
  if (!isDateTime(created)) throw new Error("created 非法時間");
  if (unsignedVc.proof !== undefined) throw new Error("文件已含 proof，請重新生成未簽名的 VC 再簽");
  // 1. Build the proof options first (there is no proofValue yet)
  const proofOptions = {
    type: "DataIntegrityProof",
    cryptosuite: keys.cryptosuite,
    created,
    verificationMethod: keys.verificationMethod ?? keys.did + "#" + suite.fragment(keys.did), // delegate keys bring their own #delegate-N
    proofPurpose: "assertionMethod",
    "@context": unsignedVc["@context"],
  };
  // 2. Hash proof options + document → 3. sign → 4. attach the proofValue
  const sig = await suite.sign(keys, await diHashData(proofOptions, unsignedVc));
  return { ...proofOptions, proofValue: "z" + base58btcEncode(sig) };
}

async function verifyProof(signedVc, ctx = {}) {
  const r = report();
  const proof = signedVc.proof;
  if (!isPlainObject(proof)) {
    r.fails.push("缺少 proof 物件（本 demo 只支援單一 proof）");
    return r;
  }
  const suite = SUITES[proof.cryptosuite];
  r.check(proof.type === "DataIntegrityProof", "proof.type 正確", 'proof.type 需為 "DataIntegrityProof"');
  if (!r.check(!!suite, `cryptosuite 為 ${proof.cryptosuite}${suite?.note ?? ""}`,
    `不支援的 cryptosuite：${proof.cryptosuite}（支援 ${Object.keys(SUITES).join("、")}）`)) return r;
  r.soft(proof.proofPurpose === "assertionMethod", "proofPurpose 為 assertionMethod",
    "proofPurpose 不是 assertionMethod（本 demo 預期 assertionMethod）");
  r.check(isDateTime(proof.created), "proof.created 為合法時間", "proof.created 非法時間");

  let sig = null;
  if (r.check(typeof proof.proofValue === "string" && proof.proofValue.startsWith("z"),
    "proofValue 為 z 開頭的 multibase base58btc", "proofValue 需為 z 開頭的 multibase base58btc")) {
    try {
      sig = base58btcDecode(proof.proofValue.slice(1));
      r.check(sig.length === suite.sigLen, `proofValue 解碼為 ${suite.sigLen}-byte 簽名`,
        `簽名長度應為 ${suite.sigLen} bytes，實際 ${sig.length}`);
    } catch (e) { r.fails.push("proofValue 解碼失敗：" + e.message); }
  }

  // verificationMethod = <DID>#<fragment>; each suite's verify() decides which fragments are valid
  const vm = proof.verificationMethod;
  let did = null, didInfo = null, fragment = null;
  if (r.check(typeof vm === "string" && vm.includes("#"), "verificationMethod 為 DID#fragment 形式",
    "verificationMethod 需為 DID 加 #fragment 形式")) {
    did = vm.slice(0, vm.indexOf("#"));
    fragment = vm.slice(vm.indexOf("#") + 1);
    try {
      didInfo = didMethodOf(did).parse(did);
      r.passes.push("verificationMethod 的 DID 解析成功");
    } catch (e) { r.fails.push("verificationMethod DID 非法：" + e.message); }
    r.check(did === signedVc.issuer, "verificationMethod 對應 VC issuer", "verificationMethod 的 DID 與 VC issuer 不一致");
  }
  if (r.fails.length) return r;

  // Transform: drop proofValue → proof options, drop proof → original document; @context comes from the proof's copy
  const { proofValue, ...proofOptions } = proof;
  const { proof: _, ...unsecured } = signedVc;
  if (proofOptions["@context"] !== undefined) {
    const pc = [].concat(proofOptions["@context"]), dc = [].concat(unsecured["@context"]);
    if (!r.check(pc.length <= dc.length && pc.every((v, i) => dc[i] === v), "@context 前綴一致",
      "文件 @context 與 proof 內 @context 副本前綴不一致")) return r;
    unsecured["@context"] = proofOptions["@context"];
  }
  await suite.verify(r, { hashData: await diHashData(proofOptions, unsecured), sig, did, didInfo, fragment, ...ctx });
  return r;
}

/* ---------- eddsa-jcs-2022 (W3C standard), shared by did:key and did:web ----------
   The DID method supplies the public key: DID_METHODS[...].ed25519Key(r, ctx) returns 32 bytes or null. */
const ED25519 = { name: "Ed25519" };

// extractable only where the private key must outlive the page (a published did:web issuer)
async function generateEd25519(extractable = false) {
  try {
    const keypair = await crypto.subtle.generateKey(ED25519, extractable, ["sign", "verify"]);
    return { privateKey: keypair.privateKey, pub: new Uint8Array(await crypto.subtle.exportKey("raw", keypair.publicKey)) };
  } catch {
    throw new Error("此瀏覽器的 WebCrypto 不支援 Ed25519，請更新瀏覽器");
  }
}

// Multikey / did:key encoding: "z" + base58btc(multicodec 0xED01 ed25519-pub + 32-byte key)
const ed25519Multibase = (pub32) => "z" + base58btcEncode(concatBytes([0xed, 0x01], pub32));

function ed25519FromMultibase(mb) {
  const raw = base58btcDecode(String(mb).replace(/^z/, ""));
  if (raw.length !== 34) throw new Error("解碼後長度應為 34 bytes，實際 " + raw.length);
  if (raw[0] !== 0xed || raw[1] !== 0x01) throw new Error("multicodec 前綴不是 0xED01（非 Ed25519）");
  return raw.slice(2);
}

SUITES["eddsa-jcs-2022"] = {
  sigLen: 64,
  fragment: (did) => didMethodOf(did).defaultFragment(did),
  note: "",

  async sign(keys, hashData) {
    return new Uint8Array(await crypto.subtle.sign(ED25519, keys.privateKey, hashData));
  },

  async verify(r, ctx) {
    const method = didMethodOf(ctx.did);
    if (!method.ed25519Key) {
      r.fails.push(`${method.name} 不使用 Ed25519 金鑰，不能搭配 eddsa-jcs-2022`);
      return;
    }
    const pub = await method.ed25519Key(r, ctx);
    if (!pub) return;
    let ok = false;
    try {
      const pubKey = await crypto.subtle.importKey("raw", pub, ED25519, false, ["verify"]);
      ok = await crypto.subtle.verify(ED25519, pubKey, ctx.sig, ctx.hashData);
    } catch (e) {
      r.fails.push("公鑰無法匯入或驗證出錯：" + e.message);
      return;
    }
    r.check(ok, "Ed25519 簽名驗證通過（未竄改 ✓ 確為 issuer 私鑰所簽 ✓）",
      "簽名驗證失敗：文件曾被竄改，或非 issuer 私鑰所簽");
  },
};

/* ---------- VC v2.0 assembly and structural checks ---------- */
function buildVc({ standard, number, scope, holderName, validUntil }, issuerDid, holderDid) {
  if (!issuerDid || !holderDid) throw new Error("請先生成 issuer + holder DID");
  if (!standard || !number || !scope || !validUntil) throw new Error("ISO 欄位不可空白");
  const subject = { id: holderDid, certificationStandard: standard, certificateNumber: number, scope };
  if (holderName) subject.name = holderName;
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:" + crypto.randomUUID(),
    type: ["VerifiableCredential", "IsoCertificationCredential"],
    issuer: issuerDid,
    validFrom: new Date().toISOString(),
    validUntil: /^\d{4}-\d{2}-\d{2}$/.test(validUntil) ? validUntil + "T00:00:00Z" : validUntil,
    credentialSubject: subject,
  };
}

function checkDid(r, did, label, soft = false) {
  try {
    const m = didMethodOf(did);
    r.passes.push(`${label} ${m.describe(m.parse(did))}`);
    return true;
  } catch (e) {
    (soft ? r.warns : r.fails).push(`${label} DID 無法解析：` + e.message);
    return false;
  }
}

/* ✗ = violates VC Data Model v2.0 (or can't be verified); ⚠ = only differs from this demo's expectations.
   form (optional) = the page's current form values and DIDs; mismatches are warnings only. */
function verifyVc(vc, form) {
  const r = report();
  if (!isPlainObject(vc)) { r.fails.push("VC 不是一個 JSON 物件"); return r; }
  const V2 = "https://www.w3.org/ns/credentials/v2";
  r.check([].concat(vc["@context"])[0] === V2, "@context 第一項為 W3C v2", `@context 第一項必須是 ${V2}`);
  r.check([].concat(vc.type).includes("VerifiableCredential"), "type 含 VerifiableCredential", 'type 必須包含 "VerifiableCredential"');
  r.soft([].concat(vc.type).includes("IsoCertificationCredential"), "type 含 IsoCertificationCredential",
    'type 沒有 "IsoCertificationCredential"（本 demo 預期）');
  if (vc.id !== undefined) {
    if (r.check(typeof vc.id === "string" && /^[a-z][a-z0-9+.-]*:\S+$/i.test(vc.id), "id 為 URL", "id 必須是 URL")) {
      r.soft(/^urn:uuid:[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(vc.id), "id 為 urn:uuid",
        "id 不是 urn:uuid（v2 允許任何 URL，本 demo 慣用 urn:uuid）");
    }
  }

  const issuerOk = checkDid(r, vc.issuer, "issuer"); // the signature can only be checked if the issuer resolves
  const subj = vc.credentialSubject;
  if (r.check(isPlainObject(subj), "有 credentialSubject", "缺 credentialSubject（v2 必填）")) {
    const holderOk = checkDid(r, subj.id, "credentialSubject.id", true);
    if (issuerOk && holderOk) r.soft(vc.issuer !== subj.id, "issuer 與 holder 不同", "issuer 與 holder 相同（自簽）");
    for (const k of ["certificationStandard", "certificateNumber", "scope"]) {
      r.soft(!!String(subj[k] ?? "").trim(), "claim 有 " + k, "缺 ISO claim：" + k);
    }
  }
  // validFrom / validUntil are optional in v2, but must be valid date-times when present
  const from = Date.parse(vc.validFrom), until = Date.parse(vc.validUntil);
  if (vc.validFrom !== undefined) r.check(!isNaN(from), "validFrom 為合法時間", "validFrom 不是合法日期時間");
  if (vc.validUntil !== undefined) r.check(!isNaN(until), "validUntil 為合法時間", "validUntil 不是合法日期時間");
  if (!isNaN(from) && !isNaN(until)) r.check(until > from, "validUntil 晚於 validFrom", "validUntil 必須晚於 validFrom");

  if (form && isPlainObject(subj)) {
    for (const [k, f] of [["certificationStandard", "standard"], ["certificateNumber", "number"], ["scope", "scope"]]) {
      r.soft(String(subj[k] ?? "") === String(form[f] ?? ""), `${k} 與表單一致`, `${k} 與目前表單不同（以 VC 內容為準）`);
    }
    if (form.validUntil) {
      r.soft(String(vc.validUntil || "").startsWith(form.validUntil.slice(0, 10)), "validUntil 與表單一致", "validUntil 與目前表單不同");
    }
    if (form.issuerDid && vc.issuer !== form.issuerDid) r.warns.push("issuer 不是頁面上目前的 DID");
    if (form.holderDid && subj.id !== form.holderDid) r.warns.push("holder 不是頁面上目前的 DID");
  }
  r.infos.push("proof" in vc ? "含 proof：一併做密碼學驗證" : "無 proof：只驗結構，無法確認是誰簽發");
  return r;
}
