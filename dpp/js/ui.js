/* DOM wiring only; all logic lives in vc.js / did-key.js / did-ethr.js. */
"use strict";

const $ = (id) => document.getElementById(id);
let issuerKeys = null, holderKeys = null; // private keys live in memory only and vanish on reload
let wallet = null; // connected MetaMask: { provider, signer, address, did }
const holderWallet = []; // signed VCs the holder keeps for presenting (card 4)

function onEl(el, handler) {
  el.addEventListener("click", async () => {
    el.disabled = true;
    try { await handler(); } finally { el.disabled = false; }
  });
}
const on = (id, handler) => onEl($(id), handler);

function showStatus(id, cls, text) {
  $(id).className = cls;
  $(id).textContent = text;
}

/* Read the chosen file as JSON (clears the input so the same file can be picked again) */
function onJsonFile(inputId, onLoad, onError) {
  $(inputId).addEventListener("change", async (ev) => {
    const f = ev.target.files[0];
    ev.target.value = "";
    if (!f) return;
    try { onLoad(JSON.parse(await f.text()), f.name); } catch (e) { onError(e); }
  });
}

function readForm() {
  const v = (id) => $(id).value.trim();
  return { standard: v("inStandard"), number: v("inNumber"), scope: v("inScope"), holderName: v("inHolderName"), validUntil: v("inValidUntil") };
}

function fillIsoForm(j) {
  const map = { certificationStandard: "inStandard", certificateNumber: "inNumber", scope: "inScope", holderName: "inHolderName", validUntil: "inValidUntil" };
  for (const [k, id] of Object.entries(map)) if (j[k]) $(id).value = j[k];
}

function renderKeys(status) {
  $("issuerDid").textContent = issuerKeys?.did ?? "尚未生成";
  $("holderDid").textContent = holderKeys?.did ?? "尚未生成";
  $("keyMethod").textContent = status;
  renderWallet(); // a new holder DID changes which wallet VCs are "mine"
  // did:web: offer the DID document for publishing at the URL the DID points to
  const doc = issuerKeys?.didDocument;
  $("webDocBox").hidden = !doc;
  if (doc) $("webDocHint").textContent = `放到 ${DID_METHODS["did:web:"].parse(doc.id).url}；私鑰檔自己保存。`;
}

/* did:web: tell the user whether the website already serves this key, a different key, or nothing yet */
async function renderWebStatus(prefix) {
  const status = await DID_METHODS["did:web:"].publishedStatus(issuerKeys);
  const notes = {
    same: "與網站上的 did.json 相符。",
    different: "⚠ 與網站上的 did.json 不符，簽的 VC 會驗證失敗。",
    unpublished: "did.json 尚未上網站，只能在本頁模擬驗證。",
  };
  renderKeys(`${prefix} ${notes[status]}`);
}

function downloadText(text, filename) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function showVc(vc) {
  $("vcOut").textContent = JSON.stringify(vc, null, 2);
  $("vcVerify").replaceChildren();
  $("qrBox").hidden = true; // a QR code for the previous VC would be stale
  const suite = vc.proof === undefined ? null : String(vc.proof.cryptosuite || "unknown suite");
  $("signBadge").textContent = suite ? "SIGNED · " + suite : "UNSIGNED";
  $("signBadge").classList.toggle("signed", !!suite);
}

/* r.errors (typed VP errors such as AudienceMismatchError) are named in the summary line.
   The individual checks fold under the summary; they start open only when something failed. */
function renderReport(r, box = $("vcVerify"), { collapsible = true } = {}) {
  box.replaceChildren();
  const names = [...new Set((r.errors ?? []).map((e) => e.name))].join("、");
  const head = document.createElement(collapsible ? "summary" : "p");
  head.className = r.fails.length ? "err summary" : "ok summary";
  head.textContent = r.fails.length
    ? `驗證失敗：${names || r.fails.length + " 項錯誤"}`
    : `驗證通過：${r.passes.length} 項檢查全過${r.warns.length ? `（另 ${r.warns.length} 項提醒）` : ""}`;
  const body = collapsible ? Object.assign(document.createElement("details"), { open: r.fails.length > 0 }) : box;
  body.append(head);
  for (const [cls, sym, list] of [["err", "✗", r.fails], ["warn", "⚠", r.warns], ["pass", "✓", r.passes], ["info", "ℹ", r.infos]]) {
    for (const t of list) body.append(Object.assign(document.createElement("div"), { className: cls, textContent: sym + " " + t }));
  }
  if (collapsible) box.append(body);
}

/* ---------- 1. ISO certificate ---------- */
$("btnFile").addEventListener("click", () => $("fileInput").click());
onJsonFile("fileInput",
  (j, name) => { fillIsoForm(j); $("fileStatus").textContent = "已匯入 " + name + "。"; },
  () => { $("fileStatus").textContent = "JSON 解析失敗。"; });

/* ---------- 2. DID ---------- */
/* One tab per DID method: show only the selected method's panel */
function renderMethod() {
  const prefix = document.querySelector('input[name="didMethod"]:checked').value;
  document.querySelectorAll(".panel").forEach((panel) => { panel.hidden = panel.dataset.method !== prefix; });
}
document.querySelectorAll('input[name="didMethod"]').forEach((el) => el.addEventListener("change", renderMethod));
renderMethod();

// Each panel's generate button names its method in data-gen
document.querySelectorAll("button[data-gen]").forEach((btn) => onEl(btn, async () => {
  $("keyMethod").textContent = "生成中…";
  try {
    const m = DID_METHODS[btn.dataset.gen];
    const holderMethod = m.holder ? DID_METHODS[m.holder] : m;
    issuerKeys = await m.generate({ domain: $("inWebDomain").value });
    holderKeys = await holderMethod.generate();
    const holderNote = holderMethod === m ? "" : `，holder 用 ${holderMethod.name}`;
    renderKeys(`✓ 已生成 ${m.name}${holderNote}，私鑰只在頁面記憶體。`);
    if (issuerKeys.didDocument) await renderWebStatus(`✓ 已生成 ${m.name}${holderNote}。`);
    $("inResolveDid").value = issuerKeys.did;
  } catch (e) {
    $("keyMethod").textContent = "生成失敗：" + e.message;
  }
}));

on("btnResolve", async () => {
  const out = $("didDocOut");
  out.hidden = false;
  out.textContent = "解析中…";
  try {
    const did = $("inResolveDid").value.trim();
    const res = await didMethodOf(did).resolve(did, { rpcUrl: $("inRpc").value.trim() || undefined });
    out.textContent = JSON.stringify(res, null, 2);
  } catch (e) {
    out.textContent = "解析失敗：" + e.message;
  }
});

on("btnWebDoc", () => downloadText(JSON.stringify(issuerKeys.didDocument, null, 2), "did.json"));

on("btnWebKey", async () => {
  try {
    const file = await DID_METHODS["did:web:"].exportKeyFile(issuerKeys);
    const host = DID_METHODS["did:web:"].parse(issuerKeys.did).host;
    downloadText(JSON.stringify(file, null, 2), `did-web-${host}.key.json`);
  } catch (e) {
    renderKeys("匯出失敗：" + e.message + "（匯入的私鑰不能再匯出，請保存原本的私鑰檔）");
  }
});

$("btnWebImport").addEventListener("click", () => $("webKeyInput").click());
onJsonFile("webKeyInput",
  async (file) => {
    try {
      issuerKeys = await DID_METHODS["did:web:"].importKeyFile(file);
      if (!holderKeys) holderKeys = await DID_METHODS["did:key:"].generate();
      $("inWebDomain").value = DID_METHODS["did:web:"].parse(issuerKeys.did).host;
      $("inResolveDid").value = issuerKeys.did;
      await renderWebStatus(`✓ 已匯入 ${issuerKeys.did} 的私鑰。`);
    } catch (e) {
      renderKeys("匯入失敗：" + e.message);
    }
  },
  () => renderKeys("匯入失敗：私鑰檔不是 JSON。"));

on("btnClearKeys", () => {
  issuerKeys = holderKeys = null;
  renderKeys("私鑰只存在頁面記憶體，重新整理就消失。");
});

/* ---------- 2b. On-chain delegation (MetaMask) ---------- */
function showWallet(cls, text, txHash) {
  showStatus("walletStatus", cls, text);
  if (!txHash) return;
  const a = document.createElement("a");
  a.href = `${ETHR.explorer}/tx/${txHash}`;
  a.target = "_blank";
  a.rel = "noopener";
  a.textContent = " Etherscan ↗";
  $("walletStatus").append(a);
}

const walletIssuer = () => (wallet && issuerKeys?.did === wallet.did ? issuerKeys : null);

on("btnWallet", async () => {
  showWallet("", "請在 MetaMask 確認連接…");
  try {
    wallet = await connectEthrWallet();
    const ethrM = DID_METHODS["did:ethr:"];
    const signer = await ethrM.generate(); // in-page signing key, to be delegated by the wallet's DID
    issuerKeys = { did: wallet.did, cryptosuite: signer.cryptosuite, signingKey: signer.signingKey, address: signer.address, viaWallet: true };
    if (!holderKeys?.did.startsWith("did:ethr:")) holderKeys = await ethrM.generate();
    document.querySelector('input[value="did:ethr:"]').checked = true;
    renderMethod();
    $("inResolveDid").value = wallet.did;
    renderKeys(`issuer = 你的 MetaMask 帳戶；簽名金鑰 ${signer.address}（未授權）`);
    showWallet("ok", `✓ 已連接 ${wallet.address}。下一步：🔗 授權。`);
  } catch (e) {
    wallet = null;
    showWallet("err", "連接失敗：" + walletErrorMessage(e));
  }
});

/* If the tx landed but the new DID document can't be read yet, remember the tx: a re-click only re-checks, never resends */
const pendingMsg = (what, e) =>
  `${what}交易已上鏈（成功），但頁面讀不到更新後的 DID 文件：${walletErrorMessage(e)}。不用重送交易，再按一次只會重新檢查。`;

on("btnDelegate", async () => {
  const keys = walletIssuer();
  if (!keys) return showWallet("err", "請先 🦊 連接 MetaMask。");
  try {
    if (!keys.delegateTx) {
      const validity = Number($("inValidity").value);
      showWallet("", "請在 MetaMask 確認交易，上鏈約需 10–30 秒…");
      keys.delegateTx = (await addEthrDelegate(wallet, keys.address, validity)).hash;
      keys.validUntil = new Date(Date.now() + validity * 1000).toLocaleString();
    }
    showWallet("", "已上鏈，更新 DID 文件中…", keys.delegateTx);
    const fragment = await waitForDelegate(wallet.did, keys.address, $("inRpc").value.trim(), true);
    keys.verificationMethod = `${wallet.did}#${fragment}`;
    showWallet("ok", `✓ 已授權為 #${fragment}，約到 ${keys.validUntil} 有效。可以到第 3 卡簽名了。`, keys.delegateTx);
    renderKeys(`issuer = 你的 MetaMask 帳戶；簽名金鑰 ${keys.address} = #${fragment}（已授權）`);
  } catch (e) {
    showWallet("err", keys.delegateTx ? pendingMsg("授權", e) : "授權失敗：" + walletErrorMessage(e), keys.delegateTx);
  }
});

on("btnRevoke", async () => {
  const keys = walletIssuer();
  if (!keys) return showWallet("err", "請先 🦊 連接 MetaMask。");
  if (!keys.delegateTx) return showWallet("err", "這把簽名金鑰還沒授權，不需要撤銷。");
  try {
    if (!keys.revokeTx) {
      showWallet("", "請在 MetaMask 確認交易…");
      keys.revokeTx = (await revokeEthrDelegate(wallet, keys.address)).hash;
    }
    showWallet("", "已上鏈，更新 DID 文件中…", keys.revokeTx);
    await waitForDelegate(wallet.did, keys.address, $("inRpc").value.trim(), false);
    const old = keys.verificationMethod, tx = keys.revokeTx;
    keys.verificationMethod = keys.delegateTx = keys.revokeTx = undefined; // allow delegating again
    showWallet("ok", `✓ 已撤銷${old ? " #" + old.split("#")[1] : ""}，它簽過的 VC 現在驗不過。`, tx);
    renderKeys(`issuer = 你的 MetaMask 帳戶；簽名金鑰 ${keys.address}（已撤銷）`);
  } catch (e) {
    showWallet("err", keys.revokeTx ? pendingMsg("撤銷", e) : "撤銷失敗：" + walletErrorMessage(e), keys.revokeTx);
  }
});

// The connection is stale once the user switches account or network in MetaMask
globalThis.ethereum?.on?.("accountsChanged", () => { if (wallet) { wallet = null; showWallet("err", "MetaMask 帳戶已切換，請重新連接。"); } });
globalThis.ethereum?.on?.("chainChanged", () => { if (wallet) { wallet = null; showWallet("err", "MetaMask 網路已切換，請重新連接。"); } });

/* ---------- 3. Issue / sign / verify ---------- */
on("btnIssue", () => {
  try {
    const vc = buildVc(readForm(), issuerKeys?.did, holderKeys?.did);
    showVc(vc);
    const { fails } = verifyVc(vc);
    showStatus("vcCheck", fails.length ? "err" : "ok",
      fails.length ? "✗ " + fails.join("；") : "✓ 已生成（未簽名）");
  } catch (e) {
    $("vcOut").textContent = "生成失敗：" + e.message;
    showStatus("vcCheck", "", "");
  }
});

on("btnSign", async () => {
  try {
    const vc = JSON.parse($("vcOut").textContent);
    if (!issuerKeys || issuerKeys.did !== vc.issuer) {
      throw new Error("這份 VC 的 issuer 不是頁面上目前的 DID，請重新生成 VC。");
    }
    if (issuerKeys.viaWallet && !issuerKeys.verificationMethod) {
      throw new Error("請先在第 2 卡 🔗 授權簽名金鑰。");
    }
    const proof = await createProof(vc, issuerKeys);
    showVc({ ...vc, proof });
    showStatus("vcCheck", "ok", `✓ 已簽名（${proof.cryptosuite}）。`);
  } catch (e) {
    showStatus("vcCheck", "err", "簽名失敗：" + e.message);
  }
});

/* form = compare against the page's form and DIDs (issuer view); omitted for a VC opened from a QR code */
async function runVerify(vc, form) {
  $("vcVerify").textContent = "驗證中…";
  const r = verifyVc(vc, form);
  if (isPlainObject(vc) && vc.proof !== undefined) {
    try {
      const pr = await verifyProof(vc, { rpcUrl: $("inRpc").value.trim() || undefined });
      for (const k of ["passes", "warns", "fails"]) r[k].push(...pr[k].map((t) => "[簽名] " + t));
    } catch (e) {
      r.fails.push("[簽名] 驗證過程出錯：" + e.message);
    }
  }
  renderReport(r);
}

on("btnVerify", async () => {
  let vc;
  try {
    vc = JSON.parse($("vcOut").textContent);
  } catch {
    $("vcVerify").replaceChildren();
    showStatus("vcCheck", "err", "請先生成或上傳一份 VC。");
    return;
  }
  await runVerify(vc, { ...readForm(), issuerDid: issuerKeys?.did, holderDid: holderKeys?.did });
});

/* ---------- Product-passport QR code: the signed VC travels inside the link ---------- */
let shareLink = "";

on("btnQr", async () => {
  let vc;
  try {
    vc = JSON.parse($("vcOut").textContent);
  } catch {
    return showStatus("vcCheck", "err", "請先生成並簽名一份 VC。");
  }
  if (vc.proof === undefined) return showStatus("vcCheck", "err", "請先簽名：沒有簽名的 VC 掃了也無法驗證是誰發的。");
  if (typeof qrcode === "undefined") return showStatus("vcCheck", "err", "QR code 函式庫沒有載入（需要網路）。");
  shareLink = `${location.origin}${location.pathname}#vc=${await packVc(vc)}`;
  let qr = null;
  for (const level of ["M", "L"]) { // prefer more error correction; fall back if the link is too long
    try { qr = qrcode(0, level); qr.addData(shareLink, "Byte"); qr.make(); break; } catch { qr = null; }
  }
  if (!qr) return showStatus("vcCheck", "err", `連結太長（${shareLink.length} 字元），放不進 QR code。`);
  $("qrImg").innerHTML = qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true });
  const local = location.protocol === "file:" || ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
  $("qrHint").textContent = local
    ? "⚠ 目前網頁開在你自己的電腦上（" + location.host + "），手機打不開這個連結；網頁放上網站後再產生一次就能掃。"
    : `連結長度 ${shareLink.length} 字元。`;
  $("qrBox").hidden = false;
  $("qrBox").scrollIntoView({ behavior: "smooth", block: "nearest" });
});

on("btnCopyLink", async () => {
  try {
    await navigator.clipboard.writeText(shareLink);
    $("qrHint").textContent = "已複製連結。";
  } catch {
    $("qrHint").textContent = "複製失敗：瀏覽器不允許存取剪貼簿。";
  }
});

/* Opened from a QR code: load the VC from #vc=… and verify it right away
   (on page load, and when a link is pasted into an already open tab, which only changes the fragment) */
async function openSharedVc() {
  const m = /^#vc=([A-Za-z0-9_-]+)$/.exec(location.hash);
  if (!m) return;
  try {
    const vc = await unpackVc(m[1]);
    showVc(vc);
    $("sharedBanner").hidden = false;
    $("vcCard").scrollIntoView({ behavior: "smooth" });
    await runVerify(vc);
  } catch (e) {
    showStatus("vcCheck", "err", "QR code 裡的證書無法讀取：" + e.message);
  }
}
window.addEventListener("hashchange", openSharedVc);
openSharedVc();

on("btnCopy", async () => {
  try {
    await navigator.clipboard.writeText($("vcOut").textContent);
    showStatus("vcCheck", "ok", "已複製。");
  } catch {
    showStatus("vcCheck", "err", "複製失敗：瀏覽器不允許存取剪貼簿。");
  }
});

on("btnDownload", () => downloadText($("vcOut").textContent, "vc.json"));

$("btnUploadVc").addEventListener("click", () => $("vcFileInput").click());
onJsonFile("vcFileInput",
  (vc, name) => {
    if (!isPlainObject(vc)) throw new Error("不是 JSON 物件");
    showVc(vc);
    showStatus("vcCheck", "ok", `已載入 ${name}${vc.proof !== undefined ? "" : "（未簽名）"}。`);
  },
  (e) => showStatus("vcCheck", "err", "VC 檔解析失敗：" + e.message));

/* ---------- 4. VP: the holder presents VCs to a verifier ---------- */
const verifiers = {
  customs: { name: "海關", v: new Verifier("did:web:customs.example") },
  shop: { name: "零售商", v: new Verifier("did:web:shop.example") },
};
const verifierBox = (key) => document.querySelector(`.verifier[data-verifier="${key}"]`);
const shortDid = (did) => (String(did).length > 34 ? String(did).slice(0, 22) + "…" + String(did).slice(-8) : String(did));

function renderWallet() {
  const list = $("walletList");
  list.replaceChildren();
  if (!holderWallet.length) {
    list.innerHTML = '<li class="hint">錢包是空的：先在第 3 卡簽好一張 VC。</li>';
    return;
  }
  holderWallet.forEach((vc, i) => {
    const li = document.createElement("li");
    const box = document.createElement("input");
    box.type = "checkbox";
    box.checked = true;
    box.dataset.index = i;
    const text = document.createElement("div");
    const s = vc.credentialSubject ?? {};
    const mine = s.id === holderKeys?.did;
    text.innerHTML = "<strong></strong><br><span class='hint'></span>";
    text.querySelector("strong").textContent = `${s.certificationStandard ?? "VC"} · ${s.certificateNumber ?? ""}`;
    text.querySelector("span").textContent = `發證：${shortDid(vc.issuer)}${mine ? "" : `　⚠ 發給 ${shortDid(s.id)}，不是目前的持有人`}`;
    li.append(box, text);
    list.append(li);
  });
}

on("btnWalletAdd", () => {
  try {
    const vc = JSON.parse($("vcOut").textContent);
    if (vc.proof === undefined) throw new Error("這張 VC 還沒簽名");
    if (holderWallet.some((x) => x.id === vc.id)) throw new Error("這張 VC 已經在錢包裡");
    holderWallet.push(vc);
    renderWallet();
    $("vpStatus").textContent = `✓ 錢包裡有 ${holderWallet.length} 張 VC。`;
  } catch (e) {
    $("vpStatus").textContent = "無法加入：" + (e instanceof SyntaxError ? "第 3 卡還沒有 VC" : e.message);
  }
});

on("btnVpSign", async () => {
  try {
    const picked = [...document.querySelectorAll("#walletList input:checked")].map((b) => holderWallet[b.dataset.index]);
    const mode = $("vpMode").value;
    let request;
    if (mode !== "static") {
      request = verifiers[mode].request;
      if (!request) throw new Error(`請先讓${verifiers[mode].name}「📨 發出請求」`);
    }
    const vp = await signVp(buildVp(holderKeys?.did, picked), holderKeys, request);
    $("vpOut").textContent = JSON.stringify(vp, null, 2);
    $("vpStatus").textContent = request
      ? `✓ 已簽署 VP（含 ${picked.length} 張 VC），綁定${verifiers[mode].name}的 challenge 與 domain。`
      : `✓ 已簽署靜態 VP（含 ${picked.length} 張 VC），沒有指定驗證者。`;
  } catch (e) {
    $("vpStatus").textContent = "簽署失敗：" + e.message;
  }
});

/* The <pre> holds the current VP, like vcOut does for the VC; before signing it holds a hint */
const currentVp = () => { try { return JSON.parse($("vpOut").textContent); } catch { return null; } };

on("btnVpCopy", async () => {
  if (!currentVp()) return void ($("vpStatus").textContent = "還沒有 VP：先按「產生並簽署 VP」。");
  try {
    await navigator.clipboard.writeText($("vpOut").textContent);
    $("vpStatus").textContent = "已複製 VP。";
  } catch {
    $("vpStatus").textContent = "複製失敗：瀏覽器不允許存取剪貼簿。";
  }
});
on("btnVpDownload", () => {
  if (!currentVp()) return void ($("vpStatus").textContent = "還沒有 VP：先按「產生並簽署 VP」。");
  downloadText($("vpOut").textContent, "vp.json");
});

for (const [key, { name, v }] of Object.entries(verifiers)) {
  const box = verifierBox(key);
  onEl(box.querySelector('[data-action="request"]'), () => {
    v.ttlMs = Number($("vpTtl").value);
    verifiers[key].request = v.createRequest();
    box.querySelector('[data-role="result"]').replaceChildren();
    renderRequests();
  });
  onEl(box.querySelector('[data-action="submit"]'), async () => {
    const result = box.querySelector('[data-role="result"]');
    const vp = currentVp();
    if (!vp) return renderReport({ fails: ["請先產生並簽署一份 VP"], warns: [], passes: [], infos: [] }, result);
    result.textContent = `${name}驗證中…`;
    renderReport(await v.verify(vp, { rpcUrl: $("inRpc").value.trim() || undefined }), result);
  });
}

/* Show each verifier's latest request with a live countdown */
function renderRequests() {
  for (const [key, { request }] of Object.entries(verifiers)) {
    const el = verifierBox(key).querySelector('[data-role="request"]');
    if (!request) { el.textContent = ""; continue; }
    const left = Math.round((Date.parse(request.expiresAt) - Date.now()) / 1000);
    el.textContent = `challenge ${request.challenge.slice(0, 10)}…　domain ${request.domain}　` +
      (left > 0 ? `剩 ${left} 秒` : "已過期");
  }
}
setInterval(renderRequests, 1000);

on("btnVpStatic", async () => {
  const vp = currentVp();
  if (!vp) return renderReport({ fails: ["請先產生並簽署一份 VP"], warns: [], passes: [], infos: [] }, $("vpStaticResult"));
  $("vpStaticResult").textContent = "驗證中…";
  renderReport(await verifyVp(vp, { rpcUrl: $("inRpc").value.trim() || undefined }), $("vpStaticResult"));
});
