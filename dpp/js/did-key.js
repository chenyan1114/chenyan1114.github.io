/* did:key (Ed25519): the public key is encoded in the DID itself, so everything works offline.
   Signs with the shared eddsa-jcs-2022 suite in vc.js. */
"use strict";

DID_METHODS["did:key:"] = {
  name: "did:key（Ed25519）",
  hint: "公鑰直接編在 DID 字串裡，不需任何註冊中心，離線可驗。",

  async generate() {
    const { privateKey, pub } = await generateEd25519();
    return { did: "did:key:" + ed25519Multibase(pub), cryptosuite: "eddsa-jcs-2022", privateKey };
  },

  parse(did) {
    if (!did.startsWith("did:key:z")) throw new Error("不是 did:key:z 開頭");
    return { pub: ed25519FromMultibase(did.slice("did:key:".length)) };
  },

  describe: () => "did:key 解碼成功（0xED01 前綴，32-byte Ed25519 公鑰）",

  defaultFragment: (did) => did.slice("did:key:".length), // did#<fingerprint of the same key>

  async ed25519Key(r, { did, didInfo, fragment }) {
    const want = this.defaultFragment(did);
    r.soft(fragment === want, `verificationMethod fragment 正確（#${want.slice(0, 12)}…）`,
      "verificationMethod fragment 與 did:key 指紋不一致（互通性警告）");
    return didInfo.pub;
  },

  /* The DID document is derived from the DID string itself; there is no registry to query. */
  async resolve(did) {
    this.parse(did);
    const vmId = did + "#" + this.defaultFragment(did);
    return {
      didDocument: {
        "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
        id: did,
        verificationMethod: [{ id: vmId, type: "Multikey", controller: did, publicKeyMultibase: this.defaultFragment(did) }],
        authentication: [vmId],
        assertionMethod: [vmId],
      },
      didDocumentMetadata: {},
      didResolutionMetadata: { note: "由 DID 字串離線推導，無註冊中心、無法更新或撤銷" },
    };
  },
};
