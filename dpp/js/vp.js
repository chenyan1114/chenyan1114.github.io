/* Verifiable Presentations (VC Data Model v2.0) with Data Integrity proofs.
   Phase 1: the holder wraps VCs into a VP and signs it (proofPurpose "authentication"), so a verifier can check
            that the presenter controls the holder DID and that every VC was issued to that holder.
   Phase 2: a Verifier issues a Presentation Request (challenge + its own identifier). The holder puts both into
            the proof as `challenge` and `domain` and signs again; the verifier rejects a VP meant for someone
            else, an unknown/expired challenge, or a challenge that was already used (replay). */
"use strict";

class AudienceMismatchError extends Error { constructor(m) { super(m); this.name = "AudienceMismatchError"; } }
class ChallengeMismatchError extends Error { constructor(m) { super(m); this.name = "ChallengeMismatchError"; } }
class ChallengeExpiredError extends Error { constructor(m) { super(m); this.name = "ChallengeExpiredError"; } }
class ChallengeReusedError extends Error { constructor(m) { super(m); this.name = "ChallengeReusedError"; } }

function buildVp(holderDid, vcs) {
  if (!holderDid) throw new Error("請先生成持有人（holder）DID");
  if (!vcs.length) throw new Error("請至少選一張 VC");
  return {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    id: "urn:uuid:" + crypto.randomUUID(),
    type: ["VerifiablePresentation"],
    holder: holderDid,
    verifiableCredential: vcs,
  };
}

/* request (optional) = a Presentation Request from a Verifier: phase 2 binds its challenge and domain */
async function signVp(vp, holderKeys, request) {
  if (holderKeys?.did !== vp.holder) throw new Error("頁面上的持有人私鑰與 VP 的 holder 不符");
  const options = { proofPurpose: "authentication" };
  if (request) Object.assign(options, { challenge: request.challenge, domain: request.domain });
  return { ...vp, proof: await createProof(vp, holderKeys, undefined, options) };
}

/* Phase-1 checks: VP structure, the holder's signature, and each VC's issuer signature plus holder binding */
async function verifyVp(vp, { rpcUrl } = {}) {
  const r = report();
  if (!isPlainObject(vp)) { r.fails.push("VP 不是一個 JSON 物件"); return r; }
  const V2 = "https://www.w3.org/ns/credentials/v2";
  r.check([].concat(vp["@context"])[0] === V2, "VP @context 第一項為 W3C v2", `VP @context 第一項必須是 ${V2}`);
  r.check([].concat(vp.type).includes("VerifiablePresentation"), "type 含 VerifiablePresentation", 'type 必須包含 "VerifiablePresentation"');
  checkDid(r, vp.holder, "holder");
  const vcs = Array.isArray(vp.verifiableCredential) ? vp.verifiableCredential : [];
  if (!r.check(vcs.length > 0, `VP 內含 ${vcs.length} 張 VC`, "VP 裡沒有任何 VC")) return r;

  const merge = (prefix, sub) => { for (const k of ["fails", "warns", "passes"]) r[k].push(...sub[k].map((t) => `[${prefix}] ${t}`)); };
  // Outer proof: signed by a key the holder DID authorizes for authentication
  merge("VP 簽章", await verifyProof(vp, { rpcUrl, purpose: "authentication", controller: vp.holder }));
  // Inner VCs: issued by their issuer, untampered, and issued to this holder
  for (const [i, vc] of vcs.entries()) {
    const label = `VC ${i + 1}`;
    if (!isPlainObject(vc)) { r.fails.push(`[${label}] 不是 JSON 物件`); continue; }
    merge(label, verifyVc(vc));
    if (vc.proof === undefined) { r.fails.push(`[${label}] 沒有簽章，無法確認發證單位`); continue; }
    merge(label, await verifyProof(vc, { rpcUrl }));
    r.check(vc.credentialSubject?.id === vp.holder, `[${label}] 持有人綁定：VC 的主體就是出示者`,
      `[${label}] 持有人綁定失敗：VC 發給 ${vc.credentialSubject?.id}，出示者卻是 ${vp.holder}`);
  }
  return r;
}

/* A verifier with its own identifier. Challenges are single-use and expire; `now` is injectable for tests. */
class Verifier {
  constructor(id, { ttlMs = 120000, now = () => Date.now() } = {}) {
    this.id = id;
    this.ttlMs = ttlMs;
    this.now = now;
    this.challenges = new Map(); // challenge → { expiresAt, used }
  }

  createRequest() {
    const challenge = base64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
    const expiresAt = this.now() + this.ttlMs;
    this.challenges.set(challenge, { expiresAt, used: false });
    return { verifier: this.id, domain: this.id, challenge, expiresAt: new Date(expiresAt).toISOString() };
  }

  /* Phase-2 verification: everything verifyVp checks, plus audience and challenge binding.
     Binding failures are also returned as typed errors in r.errors (e.g. AudienceMismatchError). */
  async verify(vp, opts) {
    const r = await verifyVp(vp, opts);
    r.errors = [];
    const fail = (err) => { r.errors.push(err); r.fails.push(`${err.name}：${err.message}`); };
    const proof = isPlainObject(vp?.proof) ? vp.proof : {};
    if (proof.domain !== this.id) {
      fail(new AudienceMismatchError(proof.domain === undefined
        ? `VP 沒有指定受眾（domain），不能證明是出示給 ${this.id} 的`
        : `這份 VP 是出示給 ${proof.domain} 的，不是給我（${this.id}）`));
    } else {
      r.passes.push(`受眾正確：domain = ${this.id}`);
    }
    const entry = this.challenges.get(proof.challenge);
    if (!entry) {
      fail(new ChallengeMismatchError(proof.challenge === undefined
        ? "VP 沒有 challenge：只回應我發出的請求才能證明是現在出示、不是舊的"
        : "challenge 不是我發出的（可能是偽造，或回應了別人的請求）"));
    } else if (entry.used) {
      fail(new ChallengeReusedError("這個 challenge 已經用過：同一份 VP 被重複提交（重放攻擊）"));
    } else if (this.now() > entry.expiresAt) {
      fail(new ChallengeExpiredError(`challenge 已在 ${new Date(entry.expiresAt).toLocaleTimeString()} 過期`));
    } else {
      r.passes.push("challenge 正確、未過期、第一次使用");
    }
    if (entry && r.fails.length === 0) entry.used = true; // consume only on a fully valid presentation
    return r;
  }
}
