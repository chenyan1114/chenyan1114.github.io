/* Card 5: EUDI wallet (e.g. Lissi) through the backend in server/ (OpenID4VCI issuance, OpenID4VP presentation).
   DOM wiring only; the protocols run on the server, this page just shows QR codes and polls for the result. */
"use strict";

const eudi = { base: "", timers: {} };

const eudiApi = async (path, body) => {
  const res = await fetch(eudi.base + path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {});
  const json = await res.json();
  if (!res.ok) throw new Error(json.error_description ?? json.error ?? res.status);
  return json;
};

/* Draw a QR code plus "open on this phone" / copy buttons for a wallet link */
function showWalletLink(boxId, link) {
  const box = $(boxId);
  box.replaceChildren();
  if (typeof qrcode !== "undefined") {
    const qr = qrcode(0, "L");
    qr.addData(link, "Byte");
    qr.make();
    box.insertAdjacentHTML("beforeend", qr.createSvgTag({ cellSize: 4, margin: 4, scalable: true }));
  }
  const p = document.createElement("p");
  const open = Object.assign(document.createElement("a"), { href: link, textContent: "📱 在這支手機打開錢包" });
  const copy = Object.assign(document.createElement("button"), { textContent: "複製連結" });
  copy.addEventListener("click", () => navigator.clipboard.writeText(link));
  p.append(open, " ", copy);
  box.append(p);
}

/* Poll until onStatus reports a final status (returns true) */
function poll(name, path, onStatus) {
  clearInterval(eudi.timers[name]);
  eudi.timers[name] = setInterval(async () => {
    try {
      if (onStatus(await eudiApi(path))) clearInterval(eudi.timers[name]);
    } catch { /* keep polling through brief network hiccups */ }
  }, 1500);
}

async function connectEudi(url) {
  eudi.base = url.trim().replace(/\/+$/, "");
  if (!eudi.base) return showStatus("eudiServerStatus", "hint", "請填後端網址（npm run server 啟動）。");
  try {
    const info = await eudiApi("/api/info");
    try { localStorage.setItem("eudiServer", eudi.base); } catch {}
    const https = info.publicUrl.startsWith("https://");
    showStatus("eudiServerStatus", https ? "pass" : "warn", https
      ? `✓ 已連線：${info.publicUrl}`
      : `⚠ 已連線，但 ${info.publicUrl} 不是 HTTPS，手機錢包連不到；請開 tunnel 並用 --public-url 重啟。`);
  } catch (e) {
    showStatus("eudiServerStatus", "err", `連不到後端：${e.message}`);
  }
}

$("eudiServer").addEventListener("change", (ev) => connectEudi(ev.target.value));

on("btnEudiOffer", async () => {
  const f = readForm();
  try {
    const { id, credentialOffer } = await eudiApi("/api/offers", {
      certificationStandard: f.standard, certificateNumber: f.number, scope: f.scope, holderName: f.holderName, validUntil: f.validUntil,
    });
    showWalletLink("eudiOfferQr", credentialOffer);
    showStatus("eudiOfferStatus", "hint", "用錢包掃描 QR code 領證（10 分鐘內有效，只能領一次）…");
    const texts = { token_issued: "錢包已換到 access token，正在領證…", issued: "✓ 憑證已發到錢包" };
    poll("offer", `/api/offers/${id}`, ({ status }) => {
      if (texts[status]) showStatus("eudiOfferStatus", status === "issued" ? "ok" : "hint", texts[status]);
      return status === "issued" || status === "unknown";
    });
  } catch (e) {
    showStatus("eudiOfferStatus", "err", "產生失敗：" + e.message);
  }
});

on("btnEudiRequest", async () => {
  try {
    const { id, authorizationRequest, clientId } = await eudiApi("/api/presentations", { clientIdPrefix: $("eudiPrefix").value });
    showWalletLink("eudiRequestQr", authorizationRequest);
    showStatus("eudiRequestStatus", "hint", `驗證者 client_id：${clientId}。用錢包掃描並同意出示（5 分鐘內有效）…`);
    $("eudiResult").replaceChildren();
    poll("request", `/api/presentations/${id}`, ({ status, report }) => {
      if (!report) return status === "unknown";
      const claims = Object.entries(report.claims ?? {}).map(([k, v]) => `揭露 ${k} = ${v}`);
      renderReport({ ...report, errors: report.errors.map((name) => ({ name })), infos: claims }, $("eudiResult"));
      showStatus("eudiRequestStatus", "hint", `驗證者 client_id：${clientId}`);
      return true;
    });
  } catch (e) {
    showStatus("eudiRequestStatus", "err", "產生失敗：" + e.message);
  }
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
