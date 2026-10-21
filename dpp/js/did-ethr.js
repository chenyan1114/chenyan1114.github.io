/* did:ethr (Sepolia) + secp256k1 recoverable signatures.
   secp256k1 / keccak256 / EIP-55 come from ethers.js v6 (loaded from a CDN by index.html).
   DID resolution uses the official ethr-did-resolver, which rebuilds the DID document from ERC-1056 registry
   events (delegates, revocations, owner changes). Registry writes (add / revoke a delegate) are sent through
   the user's MetaMask, where the user confirms and pays gas. */
"use strict";

const ETHR = {
  network: "sepolia",
  chainId: 11155111,
  registry: "0x03d5003bf0e79C5F5223588F347ebA39AfbC3818", // ERC-1056 EthereumDIDRegistry (address from ethr-did-resolver's config)
  cryptosuite: "ecdsa-secp256k1-recovery-jcs-demo",      // custom teaching name, not a W3C cryptosuite
  // Must serve old logs: publicnode keeps only ~10k blocks of logs, so older delegates would silently vanish
  defaultRpc: "https://sepolia.gateway.tenderly.co",
  // Versions must match package.json devDependencies (checked by test/test.js)
  resolverModules: [
    "https://cdn.jsdelivr.net/npm/did-resolver@5.0.1/+esm",
    "https://cdn.jsdelivr.net/npm/ethr-did-resolver@14.1.4/+esm",
  ],
  importResolver: () => Promise.all(ETHR.resolverModules.map((u) => import(u))), // test/test.js swaps in the npm copies
  registryAbi: [
    "function identityOwner(address identity) view returns (address)",
    "function addDelegate(address identity, bytes32 delegateType, address delegate, uint256 validity)",
    "function revokeDelegate(address identity, bytes32 delegateType, address delegate)",
  ],
  delegateType: "veriKey", // the resolver lists veriKey delegates under assertionMethod (may issue credentials)
  explorer: "https://sepolia.etherscan.io",
};

function requireEthers() {
  if (typeof ethers === "undefined") throw new Error("ethers.js 未載入（did:ethr 需要網路載入 CDN）");
  return ethers;
}

/* ---------- DID resolution ---------- */
const ethrResolvers = new Map(); // rpcUrl → Resolver

async function resolveDidEthr(did, rpcUrl = ETHR.defaultRpc) {
  if (!ethrResolvers.has(rpcUrl)) {
    const [{ Resolver }, { getResolver }] = await ETHR.importResolver();
    const networks = [{ name: ETHR.network, chainId: ETHR.chainId, rpcUrl, registry: ETHR.registry }];
    ethrResolvers.set(rpcUrl, new Resolver(getResolver({ networks })));
  }
  return ethrResolvers.get(rpcUrl).resolve(did);
}

/* Default DID document when nothing changed on chain: the only key is #controller = the address itself */
function defaultEthrDoc(did, address) {
  const vm = {
    id: did + "#controller",
    type: "EcdsaSecp256k1RecoveryMethod2020",
    controller: did,
    blockchainAccountId: `eip155:${ETHR.chainId}:${address}`,
  };
  return { id: did, verificationMethod: [vm], authentication: [vm.id], assertionMethod: [vm.id] };
}

/* verificationMethod entry → Ethereum address (blockchainAccountId from the resolver, or publicKeyHex for keys added as attributes) */
function methodAddress(m) {
  const e = requireEthers();
  if (m.blockchainAccountId) return e.getAddress(m.blockchainAccountId.split(":").pop());
  if (m.publicKeyHex) return e.computeAddress("0x" + m.publicKeyHex);
  throw new Error(`不支援的金鑰表示法（${m.type}），本 demo 只認 blockchainAccountId／publicKeyHex`);
}

DID_METHODS["did:ethr:"] = {
  name: "did:ethr（Sepolia）",
  hint: "did:ethr:sepolia:<以太坊地址>。任何地址天生就是 did:ethr；要改 DID 文件（授權、撤銷金鑰）才寫入鏈上合約。",

  async generate() {
    const e = requireEthers();
    const signingKey = new e.SigningKey(e.randomBytes(32));
    const address = e.computeAddress(signingKey);
    return { did: `did:ethr:${ETHR.network}:${address}`, cryptosuite: ETHR.cryptosuite, signingKey, address };
  },

  /* did:ethr:<network>:0x<address>; only Sepolia and the address form are accepted */
  parse(did) {
    const m = /^did:ethr:(?:([^:]+):)?(0x[0-9a-fA-F]+)$/.exec(did);
    if (!m) throw new Error("格式應為 did:ethr:sepolia:0x<地址>");
    const network = m[1] ?? "mainnet";
    if (network !== ETHR.network && network.toLowerCase() !== "0x" + ETHR.chainId.toString(16)) {
      throw new Error(`網路是 ${network}，本 demo 只支援 Sepolia（sepolia 或 0xaa36a7）`);
    }
    if (m[2].length === 68) throw new Error("公鑰形式的 did:ethr 本 demo 未支援，請用地址形式");
    if (m[2].length !== 42) throw new Error("識別碼不是 20-byte 以太坊地址");
    try {
      return { address: requireEthers().getAddress(m[2]) }; // mixed case is checked against the EIP-55 checksum
    } catch (e) {
      throw new Error(e.code === "INVALID_ARGUMENT" ? "地址 EIP-55 校驗碼錯誤（大小寫被改過）" : e.message);
    }
  },

  describe: ({ address }) => `did:ethr 解析成功（Sepolia，地址 ${address}）`,

  resolve(did, { rpcUrl } = {}) {
    this.parse(did);
    return resolveDidEthr(did, rpcUrl);
  },
};

/* ---------- Registry writes via MetaMask: only a DID's owner can change its DID document ---------- */
async function connectEthrWallet() {
  const e = requireEthers();
  const eth = globalThis.ethereum;
  // file:// pages have no proper origin and MetaMask's approval window crashes ("reading 'origin'")
  if (globalThis.location?.protocol === "file:") {
    throw new Error("MetaMask 無法在雙擊開啟的 file:// 頁面使用，請改用 http://localhost:<port> 或 https://chenyan1114.github.io/dpp/ 開啟");
  }
  if (!eth) throw new Error("找不到 MetaMask：請在已安裝 MetaMask 的瀏覽器開啟（頁面需為 https 或 localhost）");
  await eth.request({ method: "eth_requestAccounts" });
  const chainId = "0x" + ETHR.chainId.toString(16);
  if ((await eth.request({ method: "eth_chainId" })) !== chainId) { // skip the switch prompt when already on Sepolia
    try {
      await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId }] });
    } catch (err) {
      if (err.code !== 4902) throw err; // 4902 = chain not added to the wallet yet
      await eth.request({ method: "wallet_addEthereumChain", params: [{ chainId, chainName: "Sepolia",
        nativeCurrency: { name: "Sepolia ETH", symbol: "ETH", decimals: 18 }, rpcUrls: [ETHR.defaultRpc], blockExplorerUrls: [ETHR.explorer] }] });
    }
  }
  const provider = new e.BrowserProvider(eth); // create after switching, or ethers reports "network changed"
  const signer = await provider.getSigner();
  const address = await signer.getAddress();
  return { provider, signer, address, did: `did:ethr:${ETHR.network}:${address}` };
}

async function sendRegistryTx(wallet, method, args) {
  const e = requireEthers();
  const registry = new e.Contract(ETHR.registry, ETHR.registryAbi, wallet.signer);
  const owner = await registry.identityOwner(wallet.address);
  if (owner !== wallet.address) throw new Error(`這個 DID 的 owner 是 ${owner}，不是目前的 MetaMask 帳戶，無法修改它的 DID 文件`);
  if ((await wallet.provider.getBalance(wallet.address)) === 0n) throw new Error("帳戶沒有 Sepolia ETH 可付 gas，請先到水龍頭領取測試幣");
  const tx = await registry[method](...args); // MetaMask asks the user to confirm
  const receipt = await tx.wait();
  if (receipt.status !== 1) throw new Error("交易失敗（reverted）：" + receipt.hash);
  return receipt;
}

/* addDelegate(owner, "veriKey", signing key, validity in seconds): lets the page's key issue credentials for the DID */
function addEthrDelegate(wallet, delegate, validitySeconds) {
  return sendRegistryTx(wallet, "addDelegate",
    [wallet.address, ethers.encodeBytes32String(ETHR.delegateType), delegate, validitySeconds]);
}

function revokeEthrDelegate(wallet, delegate) {
  return sendRegistryTx(wallet, "revokeDelegate", [wallet.address, ethers.encodeBytes32String(ETHR.delegateType), delegate]);
}

function walletErrorMessage(err) {
  if (err.code === "ACTION_REJECTED" || err.code === 4001) return "你在 MetaMask 取消了操作";
  if (err.code === "INSUFFICIENT_FUNDS") return "Sepolia ETH 不足以支付 gas，請先到水龍頭領取測試幣";
  return err.shortMessage || err.message;
}

/* After a tx lands, poll until the delegate appears (present = true) or disappears (false); returns its DID-document fragment */
async function waitForDelegate(did, delegate, rpcUrl, present) {
  let problem = "";
  for (let i = 0; i < 10; i++) {
    try {
      const res = await resolveDidEthr(did, rpcUrl || ETHR.defaultRpc);
      const { error, message } = res.didResolutionMetadata ?? {};
      if (error) {
        problem = `解析錯誤 ${error}${message ? "：" + message : ""}`;
      } else {
        const m = (res.didDocument?.verificationMethod ?? []).find((v) => {
          try { return fragmentOf(v.id) !== "controller" && methodAddress(v) === delegate; } catch { return false; }
        });
        if (!!m === present) return m ? fragmentOf(m.id) : null;
        problem = present ? "DID 文件裡還沒有這把金鑰" : "DID 文件裡還有這把金鑰";
      }
    } catch (err) {
      problem = err.message; // e.g. the resolver failed to load from the CDN
    }
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
  throw new Error(`重試 10 次仍讀不到更新後的 DID 文件（最後一次：${problem}）`);
}

/* Resolve for verification: unreachable → default doc plus a warning; deactivated or other errors → fail (returns null) */
async function resolveForVerify(r, did, didInfo, rpcUrl) {
  let res;
  try {
    res = await resolveDidEthr(did, rpcUrl || ETHR.defaultRpc);
  } catch (err) {
    res = { didResolutionMetadata: { error: "internalError", message: err.message } };
  }
  const { error, message } = res.didResolutionMetadata ?? {};
  if (error === "internalError") {
    r.warns.push(`無法從 Sepolia 解析 DID 文件（${message}），改用離線預設文件：只有 #controller = DID 地址本身`);
    return defaultEthrDoc(did, didInfo.address);
  }
  if (error) {
    r.fails.push(`DID 解析失敗：${error}${message ? "（" + message + "）" : ""}`);
    return null;
  }
  const meta = res.didDocumentMetadata ?? {};
  if (meta.deactivated) {
    r.fails.push("此 DID 已在鏈上停用（owner 設為 0x0），不可再用於驗證");
    return null;
  }
  r.passes.push(meta.versionId
    ? `已從 Sepolia 解析 DID 文件（最後一次鏈上變更：區塊 ${meta.versionId}，${meta.updated}）`
    : "已從 Sepolia 解析 DID 文件（從未在鏈上變更，即預設文件）");
  return res.didDocument;
}

SUITES[ETHR.cryptosuite] = {
  sigLen: 65, // r ‖ s ‖ recId(0/1)
  fragment: () => "controller", // #controller by default; delegate keys set #delegate-N via keys.verificationMethod
  note: "（教學用，非 W3C 標準）",

  // Same hashData as eddsa-jcs-2022; ECDSA signs its SHA-256 digest (as JOSE ES256K does), RFC 6979 k, low-S
  async sign(keys, hashData) {
    const s = keys.signingKey.sign(await sha256(hashData));
    return concatBytes(ethers.getBytes(s.r), ethers.getBytes(s.s), [s.yParity]);
  },

  async verify(r, { hashData, sig, did, didInfo, fragment, rpcUrl }) {
    const e = requireEthers();
    if (!r.check(e.toBigInt(sig.slice(32, 64)) <= e.N / 2n, "s 為 low-S", "s 不是 low-S（以太坊拒收可延展簽名）")) return;
    let recovered;
    try {
      recovered = e.recoverAddress(await sha256(hashData), e.hexlify(sig));
      r.passes.push("從簽名回推出簽名者地址 " + recovered);
    } catch (err) {
      r.fails.push("簽名無法回推公鑰：" + (err.shortMessage || err.message));
      return;
    }

    const doc = await resolveForVerify(r, did, didInfo, rpcUrl);
    if (!doc) return;
    // Find the key the verificationMethod points to; it must be authorized for assertionMethod
    const m = (doc.verificationMethod ?? []).find((v) => fragmentOf(v.id) === fragment);
    if (!r.check(!!m, `DID 文件中有 #${fragment}（${m?.type}）`,
      `DID 文件裡沒有 #${fragment}（金鑰不存在、已撤銷或已過期）`)) return;
    r.check((doc.assertionMethod ?? []).some((a) => fragmentOf(a.id ?? a) === fragment),
      `#${fragment} 列在 assertionMethod（可用來簽發憑證）`, `#${fragment} 未列在 assertionMethod，不可用來簽發憑證`);
    let expected;
    try {
      expected = methodAddress(m);
    } catch (err) {
      r.fails.push(err.message);
      return;
    }
    if (fragment === "controller" && expected !== didInfo.address) {
      r.warns.push(`此 DID 的 owner 已在鏈上轉移至 ${expected}，以新 owner 為準`);
    }
    r.check(recovered === expected,
      `secp256k1 簽名驗證通過：回推地址 = #${fragment} 的地址（未竄改 ✓ 確為 issuer 授權的金鑰所簽 ✓）`,
      `簽名驗證失敗：回推地址 ${recovered} ≠ #${fragment} 的地址 ${expected}（文件曾被竄改，或非 issuer 授權的金鑰所簽）`);
  },
};
