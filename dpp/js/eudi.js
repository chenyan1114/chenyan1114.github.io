/* Card 5: EUDI wallet (e.g. Lissi) through the backend in server/ (OpenID4VCI issuance, OpenID4VP presentation).
   DOM wiring only; the protocols run on the server, this page shows two QR codes everyone can scan and a live feed. */
"use strict";

const eudi = { base: "", https: false, timer: null, shown: "" };

const eudiApi = async (path, body) => {
  const res = await fetch(eudi.base + path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {});
  const json = await res.json();
  if (!res.ok) throw new Error(json.error_description ?? json.error ?? res.status);
  return json;
};

/* Draw a QR code plus an "open on this phone" link for a wallet link */
function showWalletLink(boxId, link) {
  const box = $(boxId);
  box.replaceChildren();
  if (typeof qrcode !== "undefined") {
    const qr = qrcode(0, "M");
    qr.addData(link, "Byte");
    qr.make();
    box.insertAdjacentHTML("beforeend", qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true }));
  }
  const open = Object.assign(document.createElement("a"), { href: link, textContent: "📱 用這支手機打開錢包" });
  const p = document.createElement("p");
  p.className = "hint";
  p.append(open);
  box.append(p);
}

async function connectEudi(url) {
  eudi.base = url.trim().replace(/\/+$/, "");
  if (!eudi.base) return showStatus("eudiServerStatus", "hint", "請填後端網址（npm run server 啟動）。");
  try {
    const info = await eudiApi("/api/info");
    try { localStorage.setItem("eudiServer", eudi.base); } catch {}
    eudi.https = info.publicUrl.startsWith("https://");
    showStatus("eudiServerStatus", eudi.https ? "pass" : "warn", eudi.https
      ? `✓ 已連線：${info.publicUrl}`
      : `⚠ 已連線，但 ${info.publicUrl} 不是 HTTPS，手機錢包連不到；請開 tunnel 並用 --public-url 重啟。`);
    await startEudiDemo();
  } catch (e) {
    showStatus("eudiServerStatus", "err", `連不到後端：${e.message}`);
  }
}

/* Two QR codes everyone can scan: every scan gets its own single-use code / nonce on the server */
async function startEudiDemo() {
  const f = readForm();
  const { offer, request } = await eudiApi("/api/shared", {
    certificationStandard: f.standard, certificateNumber: f.number, scope: f.scope, holderName: f.holderName, validUntil: f.validUntil,
    clientIdPrefix: $("eudiPrefix").value,
  });
  showWalletLink("eudiOfferQr", offer.credentialOffer);
  showWalletLink("eudiRequestQr", request.authorizationRequest);
  $("eudiClientId").textContent = request.clientId;
  $("eudiStage").hidden = false;
  clearInterval(eudi.timer);
  eudi.timer = setInterval(refreshFeed, 2000);
  refreshFeed();
}

const timeOf = (ms) => new Date(ms).toLocaleTimeString("zh-TW", { hour12: false });

async function refreshFeed() {
  let feed;
  try { feed = await eudiApi("/api/feed"); } catch { return; } // keep the last view through brief network hiccups
  const issued = feed.issued.filter((o) => o.status === "issued").length;
  const ok = feed.presented.filter((p) => p.status === "verified").length;
  $("eudiIssued").textContent = `已領證 ${issued} 人`;
  $("eudiPresented").textContent = `已出示 ${feed.presented.length} 人（✓ ${ok}　✗ ${feed.presented.length - ok}）`;

  const key = feed.presented.map((p) => p.createdAt + p.status).join();
  if (key === eudi.shown) return; // re-render only when something new arrived, so opened rows stay open
  eudi.shown = key;
  const list = $("eudiFeed");
  list.replaceChildren();
  if (!feed.presented.length) list.innerHTML = '<li class="hint">還沒有人出示。</li>';
  for (const { createdAt, status, report } of feed.presented) {
    const li = document.createElement("li");
    const details = document.createElement("details");
    const summary = document.createElement("summary");
    const c = report.claims ?? {};
    summary.className = status === "verified" ? "pass" : "err";
    summary.textContent = status === "verified"
      ? `✓ ${timeOf(createdAt)}　${c.certificationStandard ?? ""}　${c.certificateNumber ?? ""}`
      : `✗ ${timeOf(createdAt)}　${report.errors.join("、") || "驗證失敗"}`;
    const box = document.createElement("div");
    const claims = Object.entries(c).map(([k, v]) => `揭露 ${k} = ${v}`);
    renderReport({ ...report, errors: report.errors.map((name) => ({ name })), infos: claims }, box, { collapsible: false }); // the row itself folds
    details.append(summary, box);
    li.append(details);
    list.append(li);
  }
}

$("eudiServer").addEventListener("change", (ev) => connectEudi(ev.target.value));
$("eudiPrefix").addEventListener("change", () => eudi.base && startEudiDemo());
on("btnEudiRestart", async () => {
  try { await startEudiDemo(); } catch (e) { showStatus("eudiServerStatus", "err", "產生失敗：" + e.message); }
});
on("btnEudiFull", async () => {
  if (document.fullscreenElement) await document.exitFullscreen();
  else await $("eudiCard").requestFullscreen();
});

/* When the page is served by the backend itself, use it; otherwise remember the last URL */
(async () => {
  let saved = "";
  try { saved = localStorage.getItem("eudiServer") ?? ""; } catch {}
  const self = location.protocol.startsWith("http") && !location.hostname.endsWith("github.io") ? location.origin : "";
  if (self) {
    try { await fetch(self + "/api/info").then((r) => r.ok ? r.json() : Promise.reject()); saved = self; } catch {}
  }
  $("eudiServer").value = saved;
  if (saved) connectEudi(saved);
})();
