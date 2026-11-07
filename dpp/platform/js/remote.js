/* Server mode: when this console is served by the platform backend (server/platform/), the services stop
   running in the browser. The page reads a snapshot of what the signed-in user may see (GET /api/v1/console/state:
   the tenant's own data plus public data, never private keys) into Store.state, so the pages render as before;
   every change goes to the API, and the snapshot is fetched again. Without a backend (GitHub Pages, a file),
   Remote.enabled stays false and the offline demo in localStorage runs unchanged. */
"use strict";

const Remote = {
  enabled: false,
  session: null, // { via, role, user, org } or null (not signed in)

  async detect() {
    if (!/^https?:$/.test(location.protocol)) return false;
    try {
      const res = await fetch("/api/v1/health", { cache: "no-store" });
      this.enabled = res.ok && (await res.json()).ok === true;
    } catch {
      this.enabled = false;
    }
    return this.enabled;
  },

  async api(method, path, body) {
    if (body === undefined && (method === "POST" || method === "PUT")) body = {}; // the server only accepts JSON writes from a session
    const res = await fetch(path, { method, credentials: "same-origin", cache: "no-store",
      headers: body !== undefined ? { "Content-Type": "application/json" } : {}, body: body !== undefined ? JSON.stringify(body) : undefined });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw Object.assign(new Error(data.error_description ?? data.error ?? `HTTP ${res.status}`), { status: res.status, body: data });
    return data;
  },

  /* Load what this user may see; the pages read it from Store.state as in the offline demo */
  async refresh() {
    const snap = await this.api("GET", "/api/v1/console/state");
    Store.state = snap.state;
    Hosting.files = new Map(Object.entries(snap.hosting));
    this.session = snap.session;
  },

  can(minRole) { return !!this.session && ["viewer", "editor", "admin"].indexOf(this.session.role) >= ["viewer", "editor", "admin"].indexOf(minRole); },

  async login(email, password) {
    await this.api("POST", "/api/v1/session", { email, password });
    await this.refresh();
  },
  async logout() {
    await this.api("DELETE", "/api/v1/session").catch(() => {});
    await this.refresh();
  },

  /* Replace the services' write paths with API calls (the read paths keep working on the snapshot) */
  install() {
    const after = async (promise) => { const r = await promise; await this.refresh(); return r; };
    const enc = encodeURIComponent;
    Store.save = () => {};
    Store.load = () => Store.state;
    Catalog.addModel = (orgId, d) => after(this.api("POST", "/api/v1/models", d));
    Catalog.addItem = (orgId, d) => after(this.api("POST", "/api/v1/items", d));
    Passports.saveDraft = (id, d) => after(this.api("PUT", `/api/v1/passports/${id}/draft`, d));
    Passports.publish = async (id) => (await after(this.api("POST", `/api/v1/passports/${id}/publish`))).passport;
    Issuance.issueIso = (cbId, holder, d) => after(this.api("POST", "/api/v1/credentials/iso", { ...d, holder }));
    Issuance.issueRepairer = (brandId, holder, { scope }) => after(this.api("POST", "/api/v1/credentials/repairer", { holder, scope }));
    Issuance.setStatus = (id, purpose, on) => after(this.api("POST", `/api/v1/credentials/${enc(id)}/status`, { purpose, on }));
    DidService.rotate = () => after(this.api("POST", "/api/v1/keys/rotate", {}));
    DidService.revoke = (keyId) => after(this.api("POST", `/api/v1/keys/${enc(keyId)}/revoke`, {}));
    Access.request = () => this.api("POST", "/api/v1/access-requests", {});
    Access.present = (orgId, request, ids) => this.api("POST", "/api/v1/wallet/presentations", { challenge: request.challenge, domain: request.domain, credentials: ids });
    Access.exchange = async (vp, upi) => {
      const { gtin, serial } = DppEngine.gs1.parse(upi);
      try {
        const r = await this.api("POST", `/api/v1/passports/${gtin}/${enc(serial)}/access`, { presentation: vp });
        await this.refresh();
        return { ok: true, ...r };
      } catch (e) {
        if (e.status === 403) return { ok: false, steps: e.body.steps ?? [{ label: "授權", ok: false, detail: e.message }], errors: e.body.errors ?? [e.body.error] };
        throw e;
      }
    };
    // Verification runs where the hosted documents live: on the server. While a demo alters this browser's copy
    // (tampered ledger, rolled-back status list), it runs here instead, so the demo shows what a verifier detects.
    const localVerify = Verify.credential.bind(Verify);
    const demoActive = () => typeof UI !== "undefined" && !!(UI.rollback || UI.tamper || UI.rewrite);
    Verify.credential = (vc, opts) => (demoActive() ? localVerify(vc, opts) : this.api("POST", "/api/v1/verify", { credential: vc }));

    // On-chain anchoring: the operator's MetaMask attests from this browser, then the server reads the attestation
    // back from the chain and records it only if it matches its own ledger / status lists
    Anchor.anchor = async (wallet) => {
      if (!(await Audit.verify()).ok) throw new Error("稽核帳本的雜湊鏈已經斷掉，不能把壞掉的鏈頭錨定上鏈");
      Anchor.claim(wallet);
      const head = Anchor.head();
      const reader = EAS.reader();
      try { await easEnsureSchema(wallet, "anchor", reader); } finally { reader.close?.(); }
      const res = await easAttest(wallet, "anchor", ["0x" + head.hash, head.seq]);
      const rec = await this.api("POST", "/api/v1/anchors", { uid: res.uid, tx: res.hash, block: res.block });
      await this.refresh();
      return rec;
    };
    StatusLedger.anchor = async (wallet) => {
      Anchor.claim(wallet);
      const pending = await StatusLedger.pending();
      if (!pending.length) throw new Error("所有狀態清單都已錨定到最新版本");
      const reader = EAS.reader();
      try { await easEnsureSchema(wallet, "statusList", reader); } finally { reader.close?.(); }
      const res = await easMultiAttest(wallet, "statusList", pending.map((p) => [p.list.url, p.digest]));
      const r = await this.api("POST", "/api/v1/status-anchors", { uids: res.uids, tx: res.hash, block: res.block });
      StatusLedger.cache = null;
      await this.refresh();
      return r.accepted;
    };
  },

  async boot() {
    this.install();
    await this.refresh();
  },
};
