/* Example tenants, trust chain, certificates and products, created on first load (or after "重設示範資料").
   Every credential is really signed and every status list really published, through the same services the UI uses. */
"use strict";

async function seedPlatform(progress) {
  const S = Store.state;
  const orgs = [
    { id: "platform", name: "DPP 平台治理委員會", kind: "root", did: "did:web:trust.dpp-platform.example" },
    { id: "taf", name: "全國認證基金會（示範）", kind: "tao", did: "did:web:taf.example" },
    { id: "tqv", name: "台灣品質驗證（示範）", kind: "cb", did: "did:web:cert.tqv.example" },
    { id: "fantech", name: "範例科技股份有限公司", kind: "brand", did: "did:web:fantech.example", resolver: "id.fantech.example", vat: "12345675" },
    { id: "repair", name: "快修維修中心", kind: "repairer", did: "did:web:repair.example", vat: "87654321" },
  ];
  for (const o of orgs) S.orgs[o.id] = { ...o, createdAt: nowIso() };

  progress("產生各組織的簽章金鑰");
  for (const o of orgs) await KMS.create(o.id);
  DidService.publishAll();

  progress("建立信任鏈：平台 → 認證機構 → 驗證機構");
  await Trust.register(null, "platform", "RootTAO", ["*"]);
  await Trust.register("platform", "taf", "TAO", ["VerifiableAccreditation"]);
  await Trust.register("taf", "tqv", "TI", ["IsoCertificationCredential"]);
  await Trust.register("platform", "fantech", "Operator",
    ["DigitalProductPassportCredential", "PassportRestrictedSection", "AuthorizedRepairerCredential"]);

  progress("驗證機構簽發 ISO 證書");
  const qms = await Issuance.issueIso("tqv", "fantech", {
    standard: "ISO 9001:2015", number: "TW-QMS-2026-0042", scope: "電源供應器與行動電源之設計與製造",
    validUntil: "2029-10-23", site: "新竹縣湖口鄉光復北路 18 號",
  });
  const ems = await Issuance.issueIso("tqv", "fantech", {
    standard: "ISO 14001:2015", number: "TW-EMS-2026-0117", scope: "電源產品製造之環境管理", validUntil: "2028-06-30",
  });

  progress("建立產品並發布護照");
  const gtin = (body13) => body13 + Catalog.checkDigit(body13);
  const gln = (body12) => body12 + Catalog.checkDigit("0" + body12);
  const psu = Catalog.addModel("fantech", { gtin: gtin("0471234500001"), name: "智慧電源供應器 PSU-650", category: "電子產品" });
  const pb = Catalog.addModel("fantech", { gtin: gtin("0471234500002"), name: "行動電源 PB-10K", category: "電池" });
  const site = `湖口一廠（GLN ${gln("471234500000")}）`;
  const a = await Catalog.addItem("fantech", { gtin: psu.gtin, serial: "SN-0001", facility: site, madeOn: "2026-09-14" });
  await Catalog.addItem("fantech", { gtin: psu.gtin, serial: "SN-0002", facility: site, madeOn: "2026-09-15" });
  const c = await Catalog.addItem("fantech", { gtin: pb.gtin, serial: "PB-0001", facility: site, madeOn: "2026-10-02" });
  for (const [item, certs] of [[a, [qms.id]], [c, [qms.id, ems.id]]]) {
    const p = Passports.ofItem(item.upi);
    p.draft.certIds = certs;
    await Passports.publish(p.id);
  }

  progress("授權維修商");
  await Issuance.issueRepairer("fantech", "repair", { scope: "PSU 與 PB 全系列" });
}
