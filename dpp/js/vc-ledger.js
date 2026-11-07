/* VC history on chain: issuing, suspending, reinstating and revoking a VC are recorded as attribute events of
   the issuer's did:ethr in the ERC-1056 registry (the same contract that already holds the key history from
   addDelegate / revokeDelegate). The record is append-only, timestamped by the chain, and only the DID's owner
   can write it, so one walk over the issuer's events gives the whole timeline.
   Event names start with "dpp/" instead of "did/", so ethr-did-resolver leaves them out of the DID document.
   "EthrVcLedgerStatus2026" is this demo's own credentialStatus type, not a W3C standard (like the secp256k1 suite). */
"use strict";

const LEDGER = {
  statusType: "EthrVcLedgerStatus2026",
  names: { issued: "dpp/vc/issued", suspended: "dpp/vc/suspended", reinstated: "dpp/vc/reinstated", revoked: "dpp/vc/revoked" },
  labels: { issued: "簽發", suspended: "暫停", reinstated: "恢復", revoked: "撤銷" },
  validity: 100 * 365 * 86400, // setAttribute takes a validity; the resolver ignores these names anyway
  read: (address, rpcUrl) => readRegistryEvents(address, rpcUrl), // test/test.js swaps in a fake chain
};

/* Every event about a VC carries keccak256(vc.id); the issuance event adds SHA-256(JCS(signed VC)) */
const vcStatusKey = (vc) => requireEthers().id(String(vc.id));
const vcDigest = async (vc) => requireEthers().hexlify(await sha256(jcs(vc)));

/* Added to the VC before signing, so the pointer to the ledger is covered by the issuer's signature */
function ledgerStatusEntry(issuerDid) {
  return { id: `${issuerDid}#vc-ledger`, type: LEDGER.statusType, registry: ETHR.registry, chainId: ETHR.chainId };
}

/* All registry events of one identity, oldest first. Follows the registry's changed() → previousChange chain,
   one block at a time, the same way ethr-did-resolver rebuilds a DID document. */
async function readRegistryEvents(address, rpcUrl = ETHR.defaultRpc) {
  const e = requireEthers();
  const provider = new e.JsonRpcProvider(rpcUrl, ETHR.chainId, { staticNetwork: true });
  try {
    const reg = new e.Contract(ETHR.registry, ETHR.registryAbi, provider);
    const topic = e.zeroPadValue(e.getAddress(address), 32);
    const events = [];
    let block = Number(await reg.changed(address));
    for (let guard = 0; block && guard < 1000; guard++) {
      const [logs, header] = await Promise.all([
        provider.getLogs({ address: ETHR.registry, topics: [null, topic], fromBlock: block, toBlock: block }),
        provider.getBlock(block),
      ]);
      if (!logs.length) throw new Error(`區塊 ${block} 讀不到事件（RPC 可能沒有保留舊區塊的 log）`);
      let next = 0;
      for (const log of logs) {
        const ev = reg.interface.parseLog(log);
        if (!ev) continue;
        const prev = Number(ev.args.previousChange);
        if (prev < block && (!next || prev < next)) next = prev; // later events in the same block point at this block
        const base = { block, time: header.timestamp, tx: log.transactionHash, logIndex: log.index };
        try {
          if (ev.name === "DIDAttributeChanged") {
            events.push({ ...base, type: "attribute", name: e.decodeBytes32String(ev.args.name), value: ev.args.value });
          } else if (ev.name === "DIDDelegateChanged") {
            events.push({ ...base, type: "delegate", delegateType: e.decodeBytes32String(ev.args.delegateType),
              delegate: ev.args.delegate, validTo: Number(ev.args.validTo) });
          } else if (ev.name === "DIDOwnerChanged") {
            events.push({ ...base, type: "owner", owner: ev.args.owner });
          }
        } catch { /* a bytes32 that isn't a string: not written by this demo, skip it */ }
      }
      block = next;
    }
    return events.sort((a, b) => a.block - b.block || a.logIndex - b.logIndex);
  } finally {
    provider.destroy();
  }
}

/* Fold the issuer's events into one VC's state: revocation is final, a suspension can be lifted */
function vcLedgerState(events, key) {
  const st = { issued: null, suspended: null, revoked: null, reinstated: false, history: [] };
  const want = key.toLowerCase();
  for (const ev of events) {
    if (ev.type !== "attribute" || !ev.name.startsWith("dpp/vc/") || ev.value.slice(0, 66).toLowerCase() !== want) continue;
    st.history.push(ev);
    if (ev.name === LEDGER.names.issued) st.issued ??= { ...ev, digest: "0x" + ev.value.slice(66) };
    else if (ev.name === LEDGER.names.revoked) st.revoked ??= ev;
    else if (ev.name === LEDGER.names.suspended) st.suspended = ev;
    else if (ev.name === LEDGER.names.reinstated) { st.suspended = null; st.reinstated = true; }
  }
  return st;
}

/* Why an action makes no sense in the current state (null = allowed); checked before asking MetaMask for gas */
function ledgerRefusal(st, action) {
  if (st.revoked) return "這張 VC 已在鏈上撤銷，撤銷無法復原，不能再變更。";
  if (action === "issued") return st.issued ? "這張 VC 已經登記過簽發。" : null;
  if (!st.issued) return "請先 ⛓ 登記簽發。";
  if (action === "suspended" && st.suspended) return "這張 VC 已經是暫停狀態。";
  if (action === "reinstated" && !st.suspended) return "這張 VC 目前沒有暫停，不需要恢復。";
  return null;
}

/* setAttribute(issuer, "dpp/vc/<action>", key [+ digest], validity); only the DID's owner can send it */
async function recordVcEvent(wallet, action, vc) {
  const e = requireEthers();
  const key = vcStatusKey(vc);
  const value = action === "issued" ? e.concat([key, await vcDigest(vc)]) : key;
  return sendRegistryTx(wallet, "setAttribute", [wallet.address, e.encodeBytes32String(LEDGER.names[action]), value, LEDGER.validity]);
}

/* One timeline row; mine = the event is about the VC whose key is given */
function describeLedgerEvent(ev, key) {
  const short = (a) => `${a.slice(0, 6)}…${a.slice(-4)}`;
  if (ev.type === "owner") {
    return { label: /^0x0+$/.test(ev.owner) ? "停用 DID（owner 設為 0x0）" : `DID owner 轉移給 ${short(ev.owner)}`, mine: false };
  }
  if (ev.type === "delegate") {
    return { label: `${ev.validTo > ev.time ? "授權" : "撤銷"}簽名金鑰 ${short(ev.delegate)}（${ev.delegateType}）`, mine: false };
  }
  const action = Object.keys(LEDGER.names).find((k) => LEDGER.names[k] === ev.name);
  if (!action) return { label: `設定屬性 ${ev.name}`, mine: false };
  const mine = !!key && ev.value.slice(0, 66).toLowerCase() === key.toLowerCase();
  return { label: `${LEDGER.labels[action]} VC${mine ? "（這張）" : " " + short(ev.value.slice(0, 66))}`, mine };
}

/* The verdict for one VC's on-chain state; shared by the ERC-1056 events here and the EAS attestations (eas.js) */
async function reportLedgerState(r, st, vc, writerNote) {
  const at = (ev) => `${ev.block ? `區塊 ${ev.block}，` : ""}${new Date(ev.time * 1000).toLocaleString()}`;
  if (st.issued) {
    r.check(st.issued.digest.toLowerCase() === (await vcDigest(vc)).toLowerCase(),
      `鏈上有簽發紀錄，內容雜湊相符（${at(st.issued)}）`, `鏈上登記的內容雜湊與這份 VC 不同（${at(st.issued)}）`);
  } else {
    r.warns.push("鏈上沒有這張 VC 的簽發紀錄（發證者還沒登記，或交易尚未上鏈）");
  }
  if (st.revoked) r.fails.push(`已被發證者撤銷（${at(st.revoked)}），撤銷無法復原`);
  else if (st.suspended) r.fails.push(`目前暫停中（${at(st.suspended)}），發證者可以恢復`);
  else r.passes.push(st.reinstated ? "曾被暫停，已恢復" : "鏈上沒有撤銷或暫停紀錄");
  if (st.history.length) r.passes.push(writerNote);
}

STATUS_METHODS[LEDGER.statusType] = {
  async check(r, vc, entry, { rpcUrl } = {}) {
    let info;
    try {
      info = DID_METHODS["did:ethr:"].parse(vc.issuer);
    } catch {
      r.fails.push(`${LEDGER.statusType} 只能用在 did:ethr 發證者（紀錄寫在 issuer 的 DID 底下）`);
      return;
    }
    if (!r.check(typeof vc.id === "string", "VC 有 id（鏈上紀錄以 keccak256(id) 為索引）", "VC 沒有 id，無法對應鏈上紀錄")) return;
    if (!r.check(String(entry.registry).toLowerCase() === ETHR.registry.toLowerCase() && Number(entry.chainId) === ETHR.chainId,
      `狀態記在 Sepolia 的 ERC-1056 合約 ${ETHR.registry}`, "credentialStatus 指向別的合約或鏈，本 demo 不認")) return;
    let events;
    try {
      events = await LEDGER.read(info.address, rpcUrl || ETHR.defaultRpc);
    } catch (err) {
      r.warns.push(`讀不到鏈上歷程（${err.shortMessage || err.message}），無法確認是否已撤銷`);
      return;
    }
    await reportLedgerState(r, vcLedgerState(events, vcStatusKey(vc)), vc, "這些紀錄只有 issuer 帳戶本人能寫入（ERC-1056 只允許 DID 的 owner）");
  },
};
