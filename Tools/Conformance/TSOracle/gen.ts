// Generates wallet-wire interop vectors from the TypeScript @bsv/sdk source.
// Each case drives the real TS WalletWireTransceiver against the real TS
// WalletWireProcessor and records every request/response frame.
// Run through generate.sh; it sets the variables read here.
const SDK = process.env.BSV_TS_SDK_PATH
const OUTPUT = process.env.BSV_TS_ORACLE_OUTPUT
const SOURCE = process.env.BSV_TS_ORACLE_SOURCE
if (!SDK || !OUTPUT || !SOURCE) {
  throw new Error('BSV_TS_SDK_PATH, BSV_TS_ORACLE_OUTPUT and BSV_TS_ORACLE_SOURCE must be set (use generate.sh)')
}
const SRC = `${SDK}/src`
const { default: ProtoWallet } = await import(`${SRC}/wallet/ProtoWallet.ts`)
const { default: PrivateKey } = await import(`${SRC}/primitives/PrivateKey.ts`)
const { default: WalletWireProcessor } = await import(`${SRC}/wallet/substrates/WalletWireProcessor.ts`)
const { default: WalletWireTransceiver } = await import(`${SRC}/wallet/substrates/WalletWireTransceiver.ts`)
const { default: Transaction } = await import(`${SRC}/transaction/Transaction.ts`)
const { default: MerklePath } = await import(`${SRC}/transaction/MerklePath.ts`)
const { default: Certificate } = await import(`${SRC}/auth/certificates/Certificate.ts`)
const { stringifyBRC100 } = await import(`${SRC}/wallet/BRC100ByteEncoding.ts`)
const { default: P2PKH } = await import(`${SRC}/script/templates/P2PKH.ts`)
const { default: LockingScript } = await import(`${SRC}/script/LockingScript.ts`)
const { default: UnlockingScript } = await import(`${SRC}/script/UnlockingScript.ts`)

const hex = (b: ArrayLike<number>) => Buffer.from(Array.from(b)).toString('hex')
const rootKey = PrivateKey.fromHex('f0efba88c117ca2614554bb676d743f413822a31e3c8d70cfcc5fff119d20a07')
const proto = new ProtoWallet(rootKey)
const certifierKey = PrivateKey.fromHex('1111111111111111111111111111111111111111111111111111111111111111')
const certifierProto = new ProtoWallet(certifierKey)
const identityKey = (await proto.getPublicKey({ identityKey: true })).publicKey
const certifierPub = (await certifierProto.getPublicKey({ identityKey: true })).publicKey
const counterpartyKey = '03458d551018414b8fe1adbcef2d0afc17e1074bfab3fdde3e1b0750bdde58a9a7'

// A one-transaction block makes a valid BUMP for the parent.
const lockingScript = new P2PKH().lock(rootKey.toPublicKey().toAddress())
const parent = new Transaction(1, [], [{ lockingScript, satoshis: 5000 }], 0)
parent.inputs = [{
  sourceTXID: '00'.repeat(32), sourceOutputIndex: 0,
  unlockingScript: UnlockingScript.fromHex('51'), sequence: 0xffffffff
}]
parent.merklePath = new MerklePath(800000, [[{ offset: 0, hash: parent.id('hex'), txid: true }]])
const child = new Transaction(1, [{
  sourceTransaction: parent, sourceOutputIndex: 0,
  unlockingScript: UnlockingScript.fromHex('51'), sequence: 0xffffffff
}], [{ lockingScript, satoshis: 4000 }], 0)
const childTxid = child.id('hex')
const childAtomic = child.toAtomicBEEF()
const childBEEF = child.toBEEF()

// Signable: the request input has no unlocking script.
const signable = new Transaction(1, [{
  sourceTransaction: parent, sourceOutputIndex: 0,
  unlockingScript: new UnlockingScript([]), sequence: 0xffffffff
}], [{ lockingScript, satoshis: 4000 }], 0)
const signableAtomic = signable.toAtomicBEEF(true)

const typeA = Buffer.alloc(32, 7).toString('base64')
const serialA = Buffer.alloc(32, 9).toString('base64')
const revocation = `${'ab'.repeat(32)}.0`
async function makeCertificate(type: string, fields: Record<string, string>) {
  const c = new Certificate(type, serialA, identityKey, certifierPub, revocation, fields)
  await c.sign(certifierProto)
  return c
}
const certA = await makeCertificate(typeA, { email: 'ZW1haWw=', name: 'bmFtZQ==' })
const certLegacy: any = await makeCertificate(typeA, { name: 'bmFtZQ==' })
certLegacy.type = 'YWJj'
const certJSON = (c: any) => ({
  type: c.type, serialNumber: c.serialNumber, subject: c.subject, certifier: c.certifier,
  revocationOutpoint: c.revocationOutpoint, fields: { ...c.fields }, signature: c.signature
})

let walletResults: Record<string, any> = {}
function stub(method: string) {
  return async (args: any) => {
    const r = walletResults[method]
    if (r === undefined) throw new Error(`no stub for ${method}`)
    if (r instanceof Error) throw r
    return typeof r === 'function' ? await r(args) : r
  }
}
const wallet: any = new Proxy(proto, {
  get(target: any, prop: string) {
    if (typeof prop === 'string' && walletResults[prop] !== undefined) return stub(prop)
    const v = target[prop]
    return typeof v === 'function' ? v.bind(target) : v
  }
})

const processor = new WalletWireProcessor(wallet)
let frames: Array<{ request: string, response: string }> = []
// The Swift processor answers call 29 (the certificate compatibility profile)
// as a processor without the profile does: code 1, "Invalid call code: 29".
// The TypeScript transceiver downgrades on exactly that frame. This wire gives
// the same answer so every recorded frame is one the Swift processor must match.
const downgrade = [1, ...Array.from(Buffer.from([21])), ...Array.from(Buffer.from('Invalid call code: 29', 'utf8')), 0]
const wire = {
  async transmitToWallet(message: number[]) {
    const response = message[0] === 29 ? downgrade : await processor.transmitToWallet(message)
    frames.push({ request: hex(message), response: hex(response) })
    return response
  }
}

type Case = {
  name: string, method: string, args: any, result?: any, error?: any,
  originator?: string, spendable?: boolean, rawRequest?: string,
  // processorOnly: the TS request carries a form the Swift ABI does not keep
  // (an omitted counterparty, an explicit false, insertion-ordered maps).
  // transceiverOnly: the Swift processor writes maps sorted, TS in insertion order.
  processorOnly?: boolean, transceiverOnly?: boolean, divergence?: string
}
const out: any[] = []
async function run(c: Case) {
  walletResults = {}
  if ('result' in c) walletResults[c.method] = c.result
  frames = []
  const transceiver = new WalletWireTransceiver(wire, c.spendable === true ? { listOutputsEncoding: 'spendable' } : {})
  const originator = c.originator ?? 'example.com'
  let outcome: any
  try {
    const r = await (transceiver as any)[c.method](c.args, originator)
    outcome = { ok: stringifyBRC100(r) }
  } catch (e: any) {
    outcome = { error: { code: e.code ?? null, message: String(e.message) } }
  }
  out.push({
    name: c.name, method: c.method, originator,
    args: stringifyBRC100(c.args),
    walletResult: 'result' in c && !(c.result instanceof Error) && typeof c.result !== 'function'
      ? stringifyBRC100(c.result) : null,
    spendable: c.spendable === true,
    processorOnly: c.processorOnly === true,
    transceiverOnly: c.transceiverOnly === true,
    divergence: c.divergence ?? null,
    outcome, frames
  })
}
async function raw(name: string, requestHex: string) {
  frames = []
  const response = await processor.transmitToWallet(Array.from(Buffer.from(requestHex, 'hex')))
  out.push({ name, method: null, raw: true, frames: [{ request: requestHex, response: hex(response) }] })
}

const txA = 'a1'.repeat(32)
const txB = 'b2'.repeat(32)
const ls = lockingScript.toHex()

// ---- actions
await run({
  name: 'createAction-txid-only', method: 'createAction',
  args: {
    description: 'Test action', labels: ['label one'],
    outputs: [{ lockingScript: ls, satoshis: 1000, outputDescription: 'Pay out', basket: 'default', tags: ['t1', 't2'], customInstructions: 'ci' }],
    lockTime: 0, version: 1,
    options: { returnTXIDOnly: true, noSend: true, knownTxids: [txA], randomizeOutputs: false, acceptDelayedBroadcast: false, signAndProcess: true, trustSelf: 'known' }
  },
  result: { txid: txA, noSendChange: [`${txA}.1`], sendWithResults: [{ txid: txA, status: 'sending' }] }
})
await run({
  name: 'createAction-sendWith-only', method: 'createAction',
  args: { description: 'Send batch', options: { sendWith: [txB] } },
  result: { sendWithResults: [{ txid: txB, status: 'unproven' }] }
})
await run({
  name: 'createAction-signable', method: 'createAction',
  args: {
    description: 'Signable action', inputBEEF: Array.from(parent.toBEEF()),
    inputs: [{ outpoint: `${parent.id('hex')}.0`, inputDescription: 'Spend parent', unlockingScriptLength: 107, sequenceNumber: 0xffffffff }],
    outputs: [{ lockingScript: ls, satoshis: 4000, outputDescription: 'Change out' }]
  },
  result: { signableTransaction: { tx: Array.from(signableAtomic), reference: 'cmVmZXJlbmNl' } }
})
await run({
  name: 'createAction-with-tx', method: 'createAction',
  args: {
    description: 'Complete action', inputBEEF: Array.from(parent.toBEEF()),
    inputs: [{ outpoint: `${parent.id('hex')}.0`, inputDescription: 'Spend parent', unlockingScript: '51', sequenceNumber: 0xffffffff }],
    outputs: [{ lockingScript: ls, satoshis: 4000, outputDescription: 'Change out' }]
  },
  result: { txid: childTxid, tx: Array.from(childAtomic) }
})
await run({
  name: 'signAction-txid', method: 'signAction',
  args: { spends: { 0: { unlockingScript: '51', sequenceNumber: 0xffffffff } }, reference: 'cmVmZXJlbmNl', options: { returnTXIDOnly: true, sendWith: [txB], noSend: false, acceptDelayedBroadcast: true } },
  result: { txid: txA, sendWithResults: [{ txid: txB, status: 'failed' }] }
})
await run({
  name: 'signAction-with-tx', method: 'signAction',
  args: { spends: { 0: { unlockingScript: '51' } }, reference: 'cmVmZXJlbmNl' },
  result: { txid: childTxid, tx: Array.from(childAtomic) }
})
await run({ name: 'abortAction-true', method: 'abortAction', args: { reference: 'cmVmZXJlbmNl' }, result: { aborted: true } })
await run({ name: 'abortAction-refused', method: 'abortAction', args: { reference: 'cmVmZXJlbmNl' }, result: { aborted: false } })
const action = {
  txid: txA, satoshis: -222, status: 'completed', isOutgoing: true, description: 'History item',
  labels: ['label one'], version: 1, lockTime: 0,
  inputs: [{ sourceOutpoint: `${txB}.0`, sourceSatoshis: 5000, sourceLockingScript: ls, unlockingScript: '51', inputDescription: 'Spent coin', sequenceNumber: 0xffffffff }],
  outputs: [{ outputIndex: 0, satoshis: 4778, lockingScript: ls, spendable: true, outputDescription: 'Change', basket: 'default', tags: ['t1'], customInstructions: 'ci' }]
}
await run({
  name: 'listActions-paged', method: 'listActions',
  args: { labels: ['label one'], labelQueryMode: 'all', includeLabels: true, includeInputs: true, includeInputSourceLockingScripts: true, includeInputUnlockingScripts: true, includeOutputs: true, includeOutputLockingScripts: true, limit: 10, offset: 5, seekPermission: false },
  result: { totalActions: 250, actions: [action] }
})
await run({
  name: 'listActions-empty-page', method: 'listActions',
  args: { labels: ['label one'] },
  result: { totalActions: 250, actions: [] }
})
await run({
  name: 'listActions-no-scripts', method: 'listActions',
  args: { labels: ['label one'], includeInputs: true, includeOutputs: true },
  result: {
    totalActions: 1, actions: [{
      txid: txA, satoshis: 10, status: 'unproven', isOutgoing: false, description: '', version: 1, lockTime: 0,
      inputs: [{ sourceOutpoint: `${txB}.3`, sourceSatoshis: 5000, inputDescription: '', sequenceNumber: 0 }],
      outputs: [{ outputIndex: 1, satoshis: 10, spendable: false, outputDescription: '', basket: '', tags: [] }]
    }]
  }
})
await run({
  name: 'internalizeAction', method: 'internalizeAction',
  args: {
    tx: Array.from(childAtomic), description: 'Receive payment', labels: ['incoming'], seekPermission: true,
    outputs: [
      { outputIndex: 0, protocol: 'wallet payment', paymentRemittance: { senderIdentityKey: counterpartyKey, derivationPrefix: 'cHJlZml4', derivationSuffix: 'c3VmZml4' } }
    ]
  },
  result: { accepted: true }
})
await run({
  name: 'internalizeAction-basket', method: 'internalizeAction',
  args: {
    tx: Array.from(childAtomic), description: 'Receive token',
    outputs: [{ outputIndex: 0, protocol: 'basket insertion', insertionRemittance: { basket: 'tokens', customInstructions: 'ci', tags: ['x'] } }]
  },
  result: { accepted: true }
})
const output = { outpoint: `${txA}.1`, satoshis: 1000, lockingScript: ls, spendable: true, customInstructions: 'ci', tags: ['t1'], labels: ['label one'] }
await run({
  name: 'listOutputs-paged', method: 'listOutputs',
  args: { basket: 'default', tags: ['t1'], tagQueryMode: 'any', include: 'locking scripts', includeCustomInstructions: true, includeTags: true, includeLabels: true, limit: 10, offset: 0, seekPermission: true },
  result: { totalOutputs: 3, outputs: [output] }
})
await run({
  name: 'listOutputs-empty-page', method: 'listOutputs',
  args: { basket: 'default' },
  result: { totalOutputs: 3, outputs: [] }
})
await run({
  name: 'listOutputs-balance', method: 'listOutputs',
  args: { basket: 'balance default' },
  result: { totalOutputs: 5000000000, outputs: [] }
})
await run({
  name: 'listOutputs-module-balance', method: 'listOutputs',
  args: { basket: 'p btms balance tokens' },
  result: { totalOutputs: 7, outputs: [] }
})
await run({
  name: 'listOutputs-beef', method: 'listOutputs',
  args: { basket: 'default', include: 'entire transactions' },
  result: { totalOutputs: 1, BEEF: Array.from(childBEEF), outputs: [{ outpoint: `${childTxid}.0`, satoshis: 4000, spendable: true }] }
})
await run({
  name: 'listOutputs-spendable-extension', method: 'listOutputs', spendable: true,
  args: { basket: 'default' },
  result: { totalOutputs: 2, outputs: [{ outpoint: `${txA}.1`, satoshis: 1000, spendable: false }] }
})
await run({
  name: 'listOutputs-unspendable-legacy', method: 'listOutputs',
  args: { basket: 'default' },
  result: { totalOutputs: 2, outputs: [{ outpoint: `${txA}.1`, satoshis: 1000, spendable: false }] }
})
await run({ name: 'relinquishOutput', method: 'relinquishOutput', args: { basket: 'default', output: `${txA}.1` }, result: { relinquished: true } })

// ---- key queries through the real ProtoWallet
await run({ name: 'getPublicKey-identity', method: 'getPublicKey', args: { identityKey: true } })
await run({ name: 'getPublicKey-derived', method: 'getPublicKey', args: { protocolID: [2, 'wire tests'], keyID: '1', counterparty: counterpartyKey, forSelf: true, seekPermission: true } })
await run({ name: 'getPublicKey-explicit-false', method: 'getPublicKey', processorOnly: true, args: { protocolID: [2, 'wire tests'], keyID: '1', counterparty: counterpartyKey, forSelf: false, privileged: false } })
await run({ name: 'getPublicKey-anyone', method: 'getPublicKey', args: { protocolID: [0, 'wire tests'], keyID: 'k', counterparty: 'anyone' } })
await run({ name: 'encrypt', method: 'encrypt', args: { protocolID: [1, 'wire tests'], keyID: '1', counterparty: 'self', plaintext: [1, 2, 3], privilegedReason: 'needed for test' } })
await run({ name: 'createHmac', method: 'createHmac', args: { protocolID: [2, 'hmac key vectors'], keyID: 'k95', counterparty: 'self', data: Array.from(Buffer.from('4252432d353620484d41432074657374', 'hex')) } })
await run({ name: 'createHmac-counterparty', method: 'createHmac', args: { protocolID: [2, 'hmac key vectors'], keyID: 'k497', counterparty: counterpartyKey, data: Array.from(Buffer.from('4252432d353620484d41432074657374', 'hex')) } })
await run({ name: 'verifyHmac-valid', method: 'verifyHmac', args: { protocolID: [2, 'hmac key vectors'], keyID: 'k95', counterparty: 'self', data: Array.from(Buffer.from('4252432d353620484d41432074657374', 'hex')), hmac: Array.from(Buffer.from('3a968ebaa25eaa4b1cfad138f96105bb1eb738defc066d01e37b32595900d48b', 'hex')) } })
await run({ name: 'verifyHmac-invalid', method: 'verifyHmac', args: { protocolID: [2, 'hmac key vectors'], keyID: 'k95', counterparty: 'self', data: Array.from(Buffer.from('4252432d353620484d41432074657374', 'hex')), hmac: Array.from(Buffer.from('054a0fc6a3b0e21b31dc627fb1d645f2eea4127dff71eac95b1f71b7cb13c787', 'hex')) } })
await run({ name: 'verifyHmac-wallet-false', method: 'verifyHmac', args: { protocolID: [2, 'hmac key vectors'], keyID: 'k95', counterparty: 'self', data: [1], hmac: Array(32).fill(0) }, result: { valid: false } })
await run({ name: 'verifySignature-wallet-false', method: 'verifySignature', args: { protocolID: [2, 'wire tests'], keyID: '1', counterparty: 'self', data: [1, 2, 3], signature: [48, 6, 2, 1, 1, 2, 1, 1] }, result: { valid: false } })
await run({ name: 'createSignature-direct-hash', method: 'createSignature', args: { protocolID: [2, 'wire tests'], keyID: '1', counterparty: 'anyone', hashToDirectlySign: Array(32).fill(5) } })
await run({ name: 'createSignature', method: 'createSignature', args: { protocolID: [2, 'wire tests'], keyID: '1', counterparty: 'anyone', data: [1, 2, 3] } })
await run({ name: 'createSignature-default-counterparty', method: 'createSignature', processorOnly: true, args: { protocolID: [2, 'wire tests'], keyID: '1', data: [1, 2, 3] } })
const sig = (await proto.createSignature({ protocolID: [2, 'wire tests'], keyID: '1', data: [1, 2, 3], counterparty: 'self' })).signature
await run({ name: 'verifySignature-valid', method: 'verifySignature', args: { protocolID: [2, 'wire tests'], keyID: '1', counterparty: 'self', data: [1, 2, 3], signature: sig, forSelf: true } })
await run({ name: 'verifySignature-default-counterparty', method: 'verifySignature', processorOnly: true, args: { protocolID: [2, 'wire tests'], keyID: '1', data: [1, 2, 3], signature: sig, forSelf: true } })
await run({ name: 'verifySignature-invalid', method: 'verifySignature', args: { protocolID: [2, 'wire tests'], keyID: '1', counterparty: 'self', data: [1, 2, 4], signature: sig, forSelf: true } })
await run({ name: 'isAuthenticated', method: 'isAuthenticated', args: {}, result: { authenticated: true } })
await run({ name: 'waitForAuthentication', method: 'waitForAuthentication', args: {}, result: { authenticated: true } })
await run({ name: 'getHeight', method: 'getHeight', args: {}, result: { height: 800000 } })
await run({ name: 'getHeaderForHeight', method: 'getHeaderForHeight', args: { height: 800000 }, result: { header: '01'.repeat(80) } })
await run({ name: 'getNetwork', method: 'getNetwork', args: {}, result: { network: 'testnet' } })
await run({ name: 'getVersion', method: 'getVersion', args: {}, result: { version: 'swift-1.0.0' } })
await run({ name: 'revealSpecificKeyLinkage-self', method: 'revealSpecificKeyLinkage', args: { counterparty: 'self', verifier: counterpartyKey, protocolID: [2, 'wire tests'], keyID: '1' } })
await run({ name: 'revealSpecificKeyLinkage-anyone', method: 'revealSpecificKeyLinkage', args: { counterparty: 'anyone', verifier: counterpartyKey, protocolID: [2, 'wire tests'], keyID: '1' } })
await run({ name: 'revealCounterpartyKeyLinkage', method: 'revealCounterpartyKeyLinkage', args: { counterparty: counterpartyKey, verifier: certifierPub, privileged: true, privilegedReason: 'audit test' } })

// ---- certificates
await run({
  name: 'acquireCertificate-direct', method: 'acquireCertificate',
  args: { ...certJSON(certA), acquisitionProtocol: 'direct', keyringRevealer: 'certifier', keyringForSubject: { email: 'a2V5MQ==', name: 'a2V5Mg==' } },
  result: certJSON(certA)
})
await run({
  name: 'listCertificates', method: 'listCertificates',
  args: { certifiers: [certifierPub], types: [typeA], limit: 10, offset: 0 },
  result: { totalCertificates: 7, certificates: [{ ...certJSON(certA), keyring: { email: 'a2V5MQ==' }, verifier: counterpartyKey }] }
})
await run({
  name: 'listCertificates-unsorted-keyring', method: 'listCertificates', transceiverOnly: true,
  args: { certifiers: [certifierPub], types: [typeA] },
  result: { totalCertificates: 1, certificates: [{ ...certJSON(certA), keyring: { name: 'a2V5Mg==', email: 'a2V5MQ==' } }] }
})
await run({
  name: 'acquireCertificate-unsorted-keyring', method: 'acquireCertificate', processorOnly: true,
  args: { ...certJSON(certA), acquisitionProtocol: 'direct', keyringRevealer: counterpartyKey, keyringForSubject: { name: 'a2V5Mg==', email: 'a2V5MQ==' }, privileged: false },
  result: certJSON(certA)
})
await run({
  name: 'acquireCertificate-issuance', method: 'acquireCertificate',
  args: { type: typeA, certifier: certifierPub, acquisitionProtocol: 'issuance', certifierUrl: 'https://certifier.example.com', fields: { email: 'a@example.com', name: 'Alice' } },
  result: certJSON(certA)
})
await run({
  name: 'acquireCertificate-issuance-unsorted', method: 'acquireCertificate', processorOnly: true,
  args: { type: typeA, certifier: certifierPub, acquisitionProtocol: 'issuance', certifierUrl: 'https://certifier.example.com', fields: { name: 'Alice', email: 'a@example.com' } },
  result: certJSON(certA)
})
await run({
  name: 'listCertificates-empty-types', method: 'listCertificates',
  args: { certifiers: [certifierPub], types: [] },
  result: { totalCertificates: 7, certificates: [] }
})
await run({
  name: 'listCertificates-legacy-type', divergence: 'legacy-certificate-type', method: 'listCertificates',
  args: { certifiers: [certifierPub], types: ['YWJj'] },
  result: { totalCertificates: 1, certificates: [certJSON(certLegacy)] }
})
await run({
  name: 'proveCertificate', method: 'proveCertificate',
  args: { certificate: certJSON(certA), fieldsToReveal: ['email'], verifier: counterpartyKey },
  result: { keyringForVerifier: { email: 'a2V5MQ==' } }
})
await run({
  name: 'proveCertificate-legacy', divergence: 'legacy-certificate-type', method: 'proveCertificate',
  args: { certificate: certJSON(certLegacy), fieldsToReveal: ['name'], verifier: counterpartyKey },
  result: { keyringForVerifier: { name: 'a2V5MQ==' } }
})
await run({
  name: 'relinquishCertificate', method: 'relinquishCertificate',
  args: { type: typeA, serialNumber: serialA, certifier: certifierPub }, result: { relinquished: true }
})
await run({
  name: 'relinquishCertificate-legacy', divergence: 'legacy-certificate-type', method: 'relinquishCertificate',
  args: { type: 'YWJj', serialNumber: serialA, certifier: certifierPub }, result: { relinquished: true }
})
const discovered = { ...certJSON(certA), certifierInfo: { name: 'Certifier', iconUrl: 'https://example.com/i.png', description: 'Trusted cert', trust: 5 }, publiclyRevealedKeyring: { email: 'a2V5MQ==' }, decryptedFields: { email: 'user@example.com' } }
await run({
  name: 'discoverByIdentityKey', method: 'discoverByIdentityKey',
  args: { identityKey, limit: 10, offset: 0 },
  result: { totalCertificates: 3, certificates: [discovered] }
})
await run({
  name: 'discoverByAttributes', method: 'discoverByAttributes',
  args: { attributes: { email: 'user@example.com' }, limit: 5, offset: 1, seekPermission: false },
  result: { totalCertificates: 1, certificates: [discovered] }
})
await run({
  name: 'discoverByAttributes-legacy', divergence: 'legacy-certificate-type', method: 'discoverByAttributes',
  args: { attributes: { name: 'Alice' } },
  result: { totalCertificates: 1, certificates: [{ ...certJSON(certLegacy), certifierInfo: discovered.certifierInfo, publiclyRevealedKeyring: { name: 'a2V5MQ==' }, decryptedFields: { name: 'Alice' } }] }
})

// ---- raw processor behaviour
await raw('unknown-call-30', '1e00')
await raw('truncated-getHeight-frame', '19')
await raw('trailing-getHeight', '190000')

await Bun.write(OUTPUT, JSON.stringify({
  source: SOURCE,
  rootKey: 'f0efba88c117ca2614554bb676d743f413822a31e3c8d70cfcc5fff119d20a07',
  cases: out
}, null, 1))
console.log(out.map(c => `${c.name}: ${c.outcome ? JSON.stringify(c.outcome).slice(0, 140) : 'raw'} frames=${c.frames.length}`).join('\n'))
