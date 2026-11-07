/* Ethereum Attestation Service (EAS): a generic, already deployed attestation contract (Sepolia, v0.26).
   Nothing is deployed by this demo. Each kind of record is a schema registered once in the SchemaRegistry
   (anyone may register it; the UID is keccak256(schema ‖ resolver ‖ revocable), so everybody gets the same UID).
   An attestation stores its attester (msg.sender), its block time and its data; only the attester can revoke it,
   and a revocation is final. Two uses here:
   - VC lifecycle (method 2): issuing = attest, revoking = revoke; suspending = a second attestation that points
     at the issuance (refUID), reinstating = revoking that suspension. credentialStatus type "EasVcStatus2026"
     is this demo's own type, not a W3C standard.
   - Audit anchoring (method 7, platform/): the head hash of the platform's audit hash chain, attested now and then.
   - Status list anchoring (platform/): the digest of every published Bitstring Status List version, several lists
     per transaction (multiAttest), so a verifier can tell a rolled-back or swapped list from the current one.
   Needs did-ethr.js (requireEthers, ETHR) and, for the status check, vc-ledger.js (vcStatusKey, reportLedgerState). */
"use strict";

const EAS = {
  address: "0xC2679fBD37d54388Ce493F1DB75320D236e1815e",        // EAS on Sepolia (its getSchemaRegistry() is the next one)
  schemaRegistry: "0x0a7E2Ff54e76B8E6659aedc9103FB21c038050D0",
  explorer: "https://sepolia.easscan.org",
  statusType: "EasVcStatus2026",
  searchFrom: 12080000, // Sepolia block when these schemas were introduced (2026-11-07); nothing under them is older
  schemas: {
    vc: { def: "bytes32 dppVcIdHash,bytes32 dppVcDigest", revocable: true, label: "VC 簽發" },
    suspension: { def: "bytes32 dppVcIdHash", revocable: true, label: "VC 暫停" },
    anchor: { def: "bytes32 dppAuditHead,uint64 dppAuditSeq", revocable: false, label: "稽核鏈頭錨定" },
    statusList: { def: "string dppStatusListUrl,bytes32 dppStatusListDigest", revocable: false, label: "狀態清單錨定" },
  },
  abi: [
    "function attest((bytes32 schema,(address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value) data) request) payable returns (bytes32)",
    "function multiAttest((bytes32 schema,(address recipient,uint64 expirationTime,bool revocable,bytes32 refUID,bytes data,uint256 value)[] data)[] multiRequests) payable returns (bytes32[])",
    "function revoke((bytes32 schema,(bytes32 uid,uint256 value) data) request) payable",
    "function getAttestation(bytes32 uid) view returns ((bytes32 uid,bytes32 schema,uint64 time,uint64 expirationTime,uint64 revocationTime,bytes32 refUID,address recipient,address attester,bool revocable,bytes data))",
    "function getSchemaRegistry() view returns (address)",
    "event Attested(address indexed recipient, address indexed attester, bytes32 uid, bytes32 indexed schema)",
    "event Revoked(address indexed recipient, address indexed attester, bytes32 uid, bytes32 indexed schema)",
  ],
  registryAbi: [
    "function register(string schema, address resolver, bool revocable) returns (bytes32)",
    "function getSchema(bytes32 uid) view returns ((bytes32 uid,address resolver,bool revocable,string schema))",
    "event Registered(bytes32 indexed uid, address registerer)",
  ],
  reader: (rpcUrl) => easReader(rpcUrl), // test/*.js swap in an in-memory contract
};

/* Schema UID exactly as the SchemaRegistry computes it (no resolver contract) */
function easSchemaUidOf(def, revocable) {
  const e = requireEthers();
  return e.solidityPackedKeccak256(["string", "address", "bool"], [def, e.ZeroAddress, revocable]);
}
const easSchemaUid = (name) => easSchemaUidOf(EAS.schemas[name].def, EAS.schemas[name].revocable);
const easTypes = (name) => EAS.schemas[name].def.split(",").map((f) => f.trim().split(" ")[0]);
const easEncode = (name, values) => requireEthers().AbiCoder.defaultAbiCoder().encode(easTypes(name), values);
const easDecode = (name, data) => requireEthers().AbiCoder.defaultAbiCoder().decode(easTypes(name), data);
const easLink = (uid) => `${EAS.explorer}/attestation/view/${uid}`;

/* Read side: schema lookup, one attestation, and the Attested / Revoked logs of one attester under one schema */
function easReader(rpcUrl = ETHR.defaultRpc) {
  const e = requireEthers();
  const provider = new e.JsonRpcProvider(rpcUrl, ETHR.chainId, { staticNetwork: true });
  const eas = new e.Contract(EAS.address, EAS.abi, provider);
  const registry = new e.Contract(EAS.schemaRegistry, EAS.registryAbi, provider);
  async function logs(event, attester, schema, fromBlock) {
    const topics = [eas.interface.getEvent(event).topicHash, null, e.zeroPadValue(e.getAddress(attester), 32), schema];
    const out = [];
    const walk = async (from, to) => { // halve the range when an RPC refuses a wide getLogs
      try {
        out.push(...await provider.getLogs({ address: EAS.address, topics, fromBlock: from, toBlock: to }));
      } catch (err) {
        if (to - from < 5000) throw err;
        const mid = Math.floor((from + to) / 2);
        await walk(from, mid);
        await walk(mid + 1, to);
      }
    };
    await walk(fromBlock, await provider.getBlockNumber());
    return out.map((l) => ({ uid: eas.interface.parseLog(l).args.uid, block: l.blockNumber, tx: l.transactionHash }));
  }
  return {
    async schemaExists(uid) { return (await registry.getSchema(uid)).uid !== e.ZeroHash; },
    async attestation(uid) {
      const a = await eas.getAttestation(uid);
      if (a.uid === e.ZeroHash) return null;
      return { uid: a.uid, schema: a.schema, time: Number(a.time), revocationTime: Number(a.revocationTime), refUID: a.refUID,
        recipient: a.recipient, attester: a.attester, revocable: a.revocable, data: a.data };
    },
    attested: (attester, schema, fromBlock) => logs("Attested", attester, schema, fromBlock),
    revoked: (attester, schema, fromBlock) => logs("Revoked", attester, schema, fromBlock),
    close() { provider.destroy(); },
  };
}

/* ---------- Writes through MetaMask (the user confirms and pays gas) ---------- */
async function sendEasTx(wallet, method, args) {
  const e = requireEthers();
  if ((await wallet.provider.getBalance(wallet.address)) === 0n) throw new Error("帳戶沒有 Sepolia ETH 可付 gas，請先到水龍頭領取測試幣");
  const target = method === "register"
    ? new e.Contract(EAS.schemaRegistry, EAS.registryAbi, wallet.signer)
    : new e.Contract(EAS.address, EAS.abi, wallet.signer);
  const tx = await target[method](...args);
  const receipt = await tx.wait();
  if (receipt.status !== 1) throw new Error("交易失敗（reverted）：" + receipt.hash);
  const uids = [];
  for (const log of receipt.logs) {
    try {
      const ev = target.interface.parseLog(log);
      if (ev?.name === "Attested" || ev?.name === "Registered") uids.push(ev.args.uid);
    } catch { /* a log of another contract */ }
  }
  return { hash: receipt.hash, block: receipt.blockNumber, uid: uids.at(-1) ?? null, uids };
}

/* Registers a schema the first time anyone needs it; null when it already exists */
async function easEnsureSchema(wallet, name, reader) {
  if (await reader.schemaExists(easSchemaUid(name))) return null;
  const s = EAS.schemas[name];
  return sendEasTx(wallet, "register", [s.def, requireEthers().ZeroAddress, s.revocable]);
}

function easAttest(wallet, name, values, { recipient, refUID } = {}) {
  const e = requireEthers();
  return sendEasTx(wallet, "attest", [{ schema: easSchemaUid(name), data: { recipient: recipient ?? e.ZeroAddress,
    expirationTime: 0, revocable: EAS.schemas[name].revocable, refUID: refUID ?? e.ZeroHash, data: easEncode(name, values), value: 0 } }]);
}

/* Several attestations under one schema in one transaction; the result's uids are in the same order */
function easMultiAttest(wallet, name, valuesList) {
  const e = requireEthers();
  const data = valuesList.map((values) => ({ recipient: e.ZeroAddress, expirationTime: 0, revocable: EAS.schemas[name].revocable,
    refUID: e.ZeroHash, data: easEncode(name, values), value: 0 }));
  return sendEasTx(wallet, "multiAttest", [[{ schema: easSchemaUid(name), data }]]);
}

const easRevoke = (wallet, name, uid) => sendEasTx(wallet, "revoke", [{ schema: easSchemaUid(name), data: { uid, value: 0 } }]);

/* ---------- VC lifecycle as attestations ---------- */
/* fromBlock: the chain head when the VC was built; its attestations can only be newer, so log searches start there */
function easStatusEntry(issuerDid, fromBlock = EAS.searchFrom) {
  return { id: `${issuerDid}#eas`, type: EAS.statusType, eas: EAS.address, schema: easSchemaUid("vc"), chainId: ETHR.chainId, fromBlock };
}

/* One VC's state, same shape as vcLedgerState (issued / suspended / revoked / reinstated / history),
   so ledgerRefusal and reportLedgerState work for both backends. Only the issuer's own attestations count. */
async function easVcState(reader, attester, vc, fromBlock) {
  const key = vcStatusKey(vc).toLowerCase();
  const from = Number.isInteger(fromBlock) ? fromBlock : EAS.searchFrom;
  const mine = (a) => a && a.attester.toLowerCase() === attester.toLowerCase();
  const txOf = (logs, uid) => logs.find((l) => l.uid === uid) ?? {};
  const st = { issued: null, suspended: null, revoked: null, reinstated: false, history: [] };
  const [vcSchema, suspSchema] = [easSchemaUid("vc"), easSchemaUid("suspension")];

  const [issuedLogs, revokedLogs] = await Promise.all([reader.attested(attester, vcSchema, from), reader.revoked(attester, vcSchema, from)]);
  for (const log of issuedLogs) { // oldest first: the first match is the issuance
    const a = await reader.attestation(log.uid);
    if (!mine(a)) continue;
    const [idHash, digest] = easDecode("vc", a.data);
    if (idHash.toLowerCase() !== key) continue;
    st.issued = { ...log, action: "issued", time: a.time, digest, revocationTime: a.revocationTime };
    break;
  }
  if (!st.issued) return st;
  st.history.push(st.issued);
  if (st.issued.revocationTime) {
    const l = txOf(revokedLogs, st.issued.uid);
    st.revoked = { uid: st.issued.uid, action: "revoked", time: st.issued.revocationTime, block: l.block, tx: l.tx };
  }

  const [suspLogs, liftLogs] = await Promise.all([reader.attested(attester, suspSchema, from), reader.revoked(attester, suspSchema, from)]);
  for (const log of suspLogs) {
    const a = await reader.attestation(log.uid);
    if (!mine(a) || a.refUID !== st.issued.uid) continue;
    const ev = { ...log, action: "suspended", time: a.time };
    st.history.push(ev);
    if (a.revocationTime) {
      const l = txOf(liftLogs, log.uid);
      st.history.push({ uid: log.uid, action: "reinstated", time: a.revocationTime, block: l.block, tx: l.tx });
      st.reinstated = true;
    } else {
      st.suspended = ev;
    }
  }
  if (st.revoked) st.history.push(st.revoked);
  st.history.sort((x, y) => x.time - y.time || (x.block ?? 0) - (y.block ?? 0));
  return st;
}

/* The transaction for one action; st is the current state (from easVcState), already checked by ledgerRefusal */
async function easRecordVcEvent(wallet, action, vc, st) {
  if (action === "issued") {
    const holder = String(vc.credentialSubject?.id ?? "");
    let recipient;
    try { if (holder.startsWith("did:ethr:")) recipient = DID_METHODS["did:ethr:"].parse(holder).address; } catch {}
    return easAttest(wallet, "vc", [vcStatusKey(vc), await vcDigest(vc)], { recipient });
  }
  if (action === "suspended") return easAttest(wallet, "suspension", [vcStatusKey(vc)], { refUID: st.issued.uid });
  if (action === "reinstated") return easRevoke(wallet, "suspension", st.suspended.uid);
  if (action === "revoked") return easRevoke(wallet, "vc", st.issued.uid);
  throw new Error("未知的動作：" + action);
}

STATUS_METHODS[EAS.statusType] = {
  async check(r, vc, entry, { rpcUrl } = {}) {
    let info;
    try {
      info = DID_METHODS["did:ethr:"].parse(vc.issuer);
    } catch {
      r.fails.push(`${EAS.statusType} 只能用在 did:ethr 發證者（attester 必須是 issuer 的地址）`);
      return;
    }
    if (!r.check(typeof vc.id === "string", "VC 有 id（attestation 以 keccak256(id) 對應這張 VC）", "VC 沒有 id，無法對應鏈上紀錄")) return;
    const ok = String(entry.eas).toLowerCase() === EAS.address.toLowerCase() && Number(entry.chainId) === ETHR.chainId && entry.schema === easSchemaUid("vc");
    if (!r.check(ok, `狀態記在 Sepolia 的 EAS 合約（schema ${String(entry.schema).slice(0, 10)}…）`, "credentialStatus 指向別的合約、鏈或 schema，本 demo 不認")) return;
    let reader, st;
    try {
      reader = EAS.reader(rpcUrl || ETHR.defaultRpc);
      st = await easVcState(reader, info.address, vc, entry.fromBlock);
    } catch (err) {
      r.warns.push(`讀不到 EAS 紀錄（${err.shortMessage || err.message}），無法確認是否已撤銷`);
      return;
    } finally {
      reader?.close?.();
    }
    await reportLedgerState(r, st, vc, "這些 attestation 的 attester 都是 issuer 帳戶本人（只有 attester 能撤銷自己的 attestation）");
  },
};
