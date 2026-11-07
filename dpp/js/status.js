/* W3C Bitstring Status List v1.0 (Recommendation, May 2025): revoking or suspending one credential.
   Each VC gets an index into two published lists (revocation, suspension). A list is itself a VC signed by the
   issuer: a bitstring of 131072 bits (16 KB, so one index reveals little), GZIP-compressed and multibase
   base64url-encoded ("u…"); bit 0 is the left-most bit of the first byte. Verifiers download the whole list, so
   the issuer never learns which credential is being checked.
   The main page uses it for did:web issuers, whose domain can host the lists next to did.json:
   did:web:example.com → https://example.com/status/revocation.json. A list signed in this page but not yet
   published is kept in STATUS.local (and localStorage) and used with a warning, like an unpublished did.json.
   platform/ uses the same encoding through statusEncode / statusDecode. */
"use strict";

const STATUS = {
  bits: 131072,
  purposes: { revocation: "撤銷", suspension: "暫停" },
  fetch: null,            // test/test.js injects a fake fetch to simulate hosting (like WEB.fetch)
  storeKey: "dppStatusLists.v1",
  local: new Map(),       // list URL → list VC signed in this page, maybe not published yet
};

try {
  for (const [url, vc] of Object.entries(JSON.parse(localStorage.getItem(STATUS.storeKey) ?? "{}"))) STATUS.local.set(url, vc);
} catch { /* no storage (tests, private windows): lists live for this page only */ }
function saveStatusLocal() {
  try { localStorage.setItem(STATUS.storeKey, JSON.stringify(Object.fromEntries(STATUS.local))); } catch {}
}

/* indices → "u" + base64url(gzip(bitstring)) */
async function statusEncode(indices, length = STATUS.bits) {
  const bits = new Uint8Array(length / 8);
  for (const i of indices) bits[i >> 3] |= 0x80 >> (i & 7);
  const gz = new Uint8Array(await new Response(new Blob([bits]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer());
  return "u" + base64urlEncode(gz);
}

async function statusDecode(encodedList) {
  if (typeof encodedList !== "string" || !encodedList.startsWith("u")) throw new Error("encodedList 應為 u 開頭的 multibase base64url");
  const raw = base64urlDecode(encodedList.slice(1));
  return new Uint8Array(await new Response(new Blob([raw]).stream().pipeThrough(new DecompressionStream("gzip"))).arrayBuffer());
}

const statusBit = (bits, i) => (bits[i >> 3] & (0x80 >> (i & 7))) !== 0;
const statusIndices = (bits) => [...bits.keys()].flatMap((b) => (bits[b] ? [0, 1, 2, 3, 4, 5, 6, 7].filter((k) => bits[b] & (0x80 >> k)).map((k) => b * 8 + k) : []));

/* did:web:host[:path] → https://host[/path]/status/<purpose>.json, next to the DID document */
function statusListUrl(issuerDid, purpose) {
  const { url } = DID_METHODS["did:web:"].parse(issuerDid);
  return url.replace(/(\.well-known\/)?did\.json$/, `status/${purpose}.json`);
}

/* The VC's credentialStatus: one random index, used in both lists */
function statusEntries(issuerDid, index = crypto.getRandomValues(new Uint32Array(1))[0] % STATUS.bits) {
  return Object.keys(STATUS.purposes).map((purpose) => {
    const url = statusListUrl(issuerDid, purpose);
    return { id: `${url}#${index}`, type: "BitstringStatusListEntry", statusPurpose: purpose, statusListIndex: String(index), statusListCredential: url };
  });
}

function buildStatusListVc(issuerDid, purpose, encodedList) {
  const url = statusListUrl(issuerDid, purpose);
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: url,
    type: ["VerifiableCredential", "BitstringStatusListCredential"],
    issuer: issuerDid,
    validFrom: new Date().toISOString(),
    credentialSubject: { id: url + "#list", type: "BitstringStatusList", statusPurpose: purpose, encodedList },
  };
}

/* The list a verifier should use: the published one, unless this page holds a different, newer one */
async function statusListFor(url) {
  let published = null, error = "";
  try {
    const res = await (STATUS.fetch ?? globalThis.fetch)(url, { cache: "no-store" });
    if (res.status === 200) published = await res.json();
    else error = `HTTP ${res.status}`;
  } catch (e) {
    error = e.message;
  }
  const local = STATUS.local.get(url);
  if (local && published && jcs(local) === jcs(published)) { // the page's copy is online now
    STATUS.local.delete(url);
    saveStatusLocal();
    return { vc: published, source: "published" };
  }
  if (local && (!published || Date.parse(local.validFrom) > Date.parse(published.validFrom))) return { vc: local, source: "local", error };
  return published ? { vc: published, source: "published" } : { vc: null, error };
}

/* Issuer side: set or clear this VC's bit and sign a new version of the list (kept in STATUS.local until published) */
async function updateStatus(keys, vc, purpose, on) {
  if (keys?.did !== vc.issuer) throw new Error("只有這張 VC 的發證者能改它的狀態：請用 issuer 的私鑰（did:web 匯入私鑰）");
  const entry = [].concat(vc.credentialStatus ?? []).find((e) => e?.type === "BitstringStatusListEntry" && e.statusPurpose === purpose);
  if (!entry) throw new Error("這張 VC 沒有狀態清單欄位（只有 did:web 發證者簽的 VC 才有）");
  const index = Number(entry.statusListIndex);
  const { vc: current } = await statusListFor(entry.statusListCredential);
  let set = [];
  if (current) {
    const res = await verifyProof(current);
    if (res.fails.length || current.issuer !== vc.issuer) throw new Error("目前的狀態清單驗證不過，無法在它上面修改：" + (res.fails[0] ?? "issuer 不同"));
    set = statusIndices(await statusDecode(current.credentialSubject.encodedList));
  }
  const was = set.includes(index);
  if (purpose === "revocation" && was && !on) throw new Error("撤銷無法復原（W3C 規範：revocation 不可逆）");
  if (was === on) throw new Error(on ? `這張 VC 已經是${STATUS.purposes[purpose]}狀態` : `這張 VC 目前沒有${STATUS.purposes[purpose]}`);
  const next = on ? [...set, index] : set.filter((i) => i !== index);
  const unsigned = buildStatusListVc(vc.issuer, purpose, await statusEncode(next));
  const signed = { ...unsigned, proof: await createProof(unsigned, keys) };
  STATUS.local.set(signed.id, signed);
  saveStatusLocal();
  return signed;
}

STATUS_METHODS.BitstringStatusListEntry = {
  async check(r, vc, entry, ctx = {}) {
    const name = STATUS.purposes[entry.statusPurpose];
    if (!name) {
      r.warns.push(`不支援的 statusPurpose「${entry.statusPurpose}」，略過`);
      return;
    }
    const tag = `${name}清單`;
    const index = Number(entry.statusListIndex);
    if (!r.check(/^\d+$/.test(String(entry.statusListIndex)) && typeof entry.statusListCredential === "string",
      `${tag}：index ${index}`, `${tag}：statusListIndex 必須是數字字串、statusListCredential 必須是網址`)) return;
    const { vc: list, source, error } = await statusListFor(entry.statusListCredential);
    if (!list) {
      r.warns.push(`${tag}：取不到 ${entry.statusListCredential}（${error}），無法確認是否已${name}`);
      return;
    }
    const pr = await verifyProof(list, ctx);
    if (!r.check(!pr.fails.length, `${tag}：清單本身的簽章正確`, `${tag}：清單本身的簽章無效（${pr.fails[0]}）`)) return;
    const issuerOf = (x) => (typeof x?.issuer === "string" ? x.issuer : x?.issuer?.id);
    if (!r.check(issuerOf(list) === issuerOf(vc), `${tag}：清單和 VC 是同一個發證者`, `${tag}：清單不是這張 VC 的發證者發布的`)) return;
    const subject = list.credentialSubject ?? {};
    if (!r.check([].concat(list.type).includes("BitstringStatusListCredential") && subject.statusPurpose === entry.statusPurpose,
      `${tag}：清單類型與用途相符`, `${tag}：清單類型或 statusPurpose 和 credentialStatus 不符`)) return;
    if (list.validUntil && Date.now() > Date.parse(list.validUntil)) r.warns.push(`${tag}：清單已過期（${list.validUntil}），可能不是最新狀態`);
    let bits;
    try {
      bits = await statusDecode(subject.encodedList);
    } catch (e) {
      r.fails.push(`${tag}：encodedList 無法解碼（${e.message}）`);
      return;
    }
    if (!r.check(bits.length * 8 >= STATUS.bits && index < bits.length * 8, `${tag}：清單長度 ${bits.length * 8} 位元`, `${tag}：index 超出清單長度，或清單短於 131072 位元`)) return;
    if (source === "local") r.warns.push(`${tag}：${entry.statusListCredential} 上還不是這一版（${error || "網站上是舊版"}），改用本頁暫存的清單；其他人驗證會看到舊狀態`);
    if (statusBit(bits, index)) r.fails.push(entry.statusPurpose === "revocation" ? "已被發證者撤銷（撤銷無法復原）" : "目前暫停中，發證者可以恢復");
    else r.passes.push(`${tag}：未${name}`);
  },
};
