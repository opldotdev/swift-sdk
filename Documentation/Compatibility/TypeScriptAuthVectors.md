# TypeScript `@bsv/sdk` 4.1.1 authentication vectors

`Tests/BSVAuthTests/BRC103/TypeScriptAuthVectors.swift` holds BRC-103 and
BRC-104 messages produced by executing `@bsv/sdk` 4.1.1 (`packages/sdk` in the
`ts-stack` repository at `3b1abc5691c0848eb00eaf5e8f018e8a7a26d5f1`). The
inputs (keys 3, 7 and 11, certificate fields, nonces from a fixed random
stream) are chosen here. The file contains program output only: no TypeScript
source text or upstream fixture is copied. `TypeScriptInteropTests` replays the
messages against this SDK. COMP-041, COMP-052, COMP-059 and COMP-060 record the
rulings they check.

## Provenance and license

`ts-stack` was relicensed under the Apache License 2.0 in commit `4760b26d0`
("Relicense under Apache License 2.0 (#1560)", 2026-11-11), an ancestor of the
pinned commit. `packages/sdk/package.json` at that commit declares version
4.1.1 and license `Apache-2.0`; its NOTICE reads "Copyright 2020-2026 BSV
Association". The vectors are recorded from running that source with the
generator below, under the fixture policy in
[FixtureSources.md](FixtureSources.md#recorded-typescript-auth-vectors) and
[VectorInventory.md](VectorInventory.md#recorded-typescript-auth-vectors).

`LocaleCompareOrderTests` holds SHA-256 digests and sorted lists printed by
`collate-vec.ts` under Bun 1.4.4 and Node 22.23.4 (ICU, locale `en-US`). Both
runtimes printed the same output.

The vectors cover:

- a `Peer` initialResponse to a Swift initialRequest, with a 48-byte session
  nonce and a handshake certificate policy;
- a `Peer` certificateResponse whose `fields` are in issue order and whose
  `keyring` is in reveal order, with the field name `a&b<c>`;
- a `Peer` certificateRequest whose types are not in byte order;
- the `AuthFetch` handshake body and the six headers of its bodyless GET;
- `AuthFetch.serializeRequest` payloads for the JSON `{}` default, an empty
  body, a `content-type` with spaces and parameters, `multipart/form-data`, and
  signed headers whose `localeCompare` order differs from byte order;
- a `Peer` with no listener answering a Swift initialRequest that carries a
  certificate policy, with its wallet's certificate inside initialResponse;
  the certificate has the fields `Zip`, `age`, `a-b` and `a_b`;
- a `Peer` initiator's initialRequest and a certificateRequest with no
  certifiers;
- a certificate signed by `Certificate.sign` with mixed-case and punctuated
  field names, and its unsigned binary.
- an `AuthFetch` client with a certificate in its wallet answering the
  certificate policy in a Swift server's initialResponse: its initialRequest,
  the initialResponse the Swift server signs, the certificateResponse
  `AuthFetch` posts on its own (fields `Zip` and `age` revealed, `name`
  withheld), and the headers of the GET that follows.

## Regenerating

Run the scripts below with Bun from one directory. `TS_SDK` names the
`packages/sdk` directory of the pinned checkout. `det.ts` replaces
`crypto.getRandomValues` with a SHA-256 counter stream, so every run gives the
same nonces.

```sh
export TS_SDK=/path/to/ts-stack/packages/sdk
bun run gen.ts > vectors.json
python3 toswift.py vectors.json Tests/BSVAuthTests/BRC103/TypeScriptAuthVectors.swift
```

`collate-vec.ts` needs no SDK. Its output is compared by hand with the values
in `LocaleCompareOrderTests`; under Node it runs as
`node --experimental-strip-types` on a `.mts` copy.

```sh
bun run collate-vec.ts
```

## Checking Swift messages with TypeScript

`TypeScriptInteropTests.swiftMessagesForTypeScript` writes the messages this SDK
sends in the first two sessions when `BSV_TS_INTEROP_DUMP` names an output file.
`verify.ts` reproduces each TypeScript session from the fixed random stream and
feeds those messages to a live `Peer` and `AuthFetch`. It checks that `Peer`
verifies the Swift certificate response, validates its certificate, verifies the
certificate request and delivers the general message, and that `AuthFetch`
accepts the Swift initialResponse and a signed 204 response with an empty body.

```sh
BSV_TS_INTEROP_DUMP=$PWD/swift-dump.json swift test --filter TypeScriptInterop
bun run verify.ts swift-dump.json vectors.json
```

The Swift certificate in that session has the field names `Zip`, `age`, `email`
and `a&b<c>`, which `localeCompare` and byte order sort differently.
`Certificate.verify` in TypeScript accepts it because this SDK signs certificate
fields in `localeCompare` order (COMP-041).

## `det.ts`

```ts
// Deterministic randomness for reproducible vectors: a SHA-256 counter stream.
import { createHash } from 'node:crypto'
let seed = 0
let counter = 0
export function resetRandom (s: number): void { seed = s; counter = 0 }
const fill = (arr: Uint8Array): Uint8Array => {
  let offset = 0
  while (offset < arr.length) {
    const block = createHash('sha256').update(`bsv-auth-vectors:${seed}:${counter++}`).digest()
    const n = Math.min(block.length, arr.length - offset)
    arr.set(block.subarray(0, n), offset)
    offset += n
  }
  return arr
}
Object.defineProperty(globalThis.crypto, 'getRandomValues', { value: fill, configurable: true, writable: true })
```

## `gen.ts`

```ts
// Generates BRC-103/104 interop vectors from the live @bsv/sdk 4.1.1 source.
import { resetRandom } from './det.ts'
const {
  PrivateKey, ProtoWallet, Peer, AuthFetch, MasterCertificate, VerifiableCertificate, Certificate, Utils
} = await import(`${process.env.TS_SDK}/mod.ts`)

const b64 = (bytes: number[]) => Utils.toBase64(bytes)
const fill = (v: number, n: number) => new Array(n).fill(v)
const key = (n: number) => new PrivateKey(n)
const tsKey = key(3); const swiftKey = key(7); const certifierKey = key(11)
const tsWallet = new ProtoWallet(tsKey)
const swiftWallet = new ProtoWallet(swiftKey)
const certifierWallet = new ProtoWallet(certifierKey)
const T = tsKey.toPublicKey().toString()
const S = swiftKey.toPublicKey().toString()
const C = certifierKey.toPublicKey().toString()
const out: Record<string, unknown> = { tsIdentity: T, swiftIdentity: S, certifier: C }

// ---------------- Scenario 1: Swift initiator <-> TS Peer responder ----------------
{
  resetRandom(1)
  const sent: any[] = []
  let onData: (m: any) => Promise<void> = async () => {}
  const transport = {
    send: async (m: any) => { sent.push(JSON.stringify(m)) },
    onData: async (cb: any) => { onData = cb }
  }
  const handshakeType = b64(fill(0x51, 32))
  const server = new Peer(tsWallet, transport, { certifiers: [C], types: { [handshakeType]: ['email'] } })
  await server.ready

  // Swift deterministic random: call k of the client returns bytes 0x40 + k.
  const swiftSessionNonce = b64(fill(0x41, 48))
  await onData({ version: '0.1', messageType: 'initialRequest', identityKey: S, initialNonce: swiftSessionNonce })
  out.initialResponse = sent.shift()
  const tsSessionNonce = JSON.parse(out.initialResponse as string).initialNonce as string

  // Certificate issued by the certifier to the TS peer, fields inserted out of byte order.
  const certType = b64(fill(0x61, 32))
  const serial = b64(fill(0x62, 32))
  const plaintext: Record<string, string> = { userName: 'Alice', profilePhoto: 'https://example.test/p.png', 'a&b<c>': 'x>y' }
  const master = await MasterCertificate.issueCertificateForSubject(
    certifierWallet, T, plaintext, certType, async () => '00'.repeat(32) + '.0', serial)
  const keyring = await MasterCertificate.createKeyringForVerifier(
    tsWallet, C, S, master.fields, ['profilePhoto', 'a&b<c>', 'userName'], master.masterKeyring, serial)
  const vc = new VerifiableCertificate(master.type, master.serialNumber, master.subject, master.certifier,
    master.revocationOutpoint, master.fields, keyring, master.signature)
  out.certificateFieldOrder = Object.keys(master.fields)
  out.certificateKeyringOrder = Object.keys(keyring)
  out.certificatePlaintext = plaintext

  server.listenForCertificatesRequested(async (sender: string) => {
    await server.sendCertificateResponse(sender, [vc])
  })

  // The Swift client's certificateRequest, built exactly as Swift writes it (call 3 -> 0x43).
  const swiftRequest = { certifiers: [C], types: { [certType]: ['userName', 'profilePhoto', 'a&b<c>'] } }
  const requestNonce = b64(fill(0x43, 32))
  const { signature } = await swiftWallet.createSignature({
    data: Utils.toArray(JSON.stringify(swiftRequest), 'utf8'),
    protocolID: [2, 'auth message signature'],
    keyID: `${requestNonce} ${tsSessionNonce}`,
    counterparty: T
  })
  await onData({
    version: '0.1', messageType: 'certificateRequest', identityKey: S, nonce: requestNonce,
    initialNonce: swiftSessionNonce, yourNonce: tsSessionNonce, requestedCertificates: swiftRequest, signature
  })
  out.certificateResponse = sent.shift()

  // TS-originated certificate request with types inserted B then A (A < B in bytes).
  const typeA = b64(fill(0x01, 32)); const typeB = b64(fill(0x02, 32))
  await server.requestCertificates({ certifiers: [C], types: { [typeB]: ['name', 'email'], [typeA]: ['x'] } }, S)
  out.certificateRequest = sent.shift()
  out.leftover = sent.length
}

// ---------------- Scenario 2: TS AuthFetch client -> Swift server ----------------
{
  resetRandom(2)
  const captured: any[] = []
  const serverNonce = b64(fill(0x61, 48)) // Swift server call 1 -> 0x61
  const fetchMock = async (url: string, init: any) => {
    const headers: Record<string, string> = {}
    new Headers(init.headers).forEach((v, k) => { headers[k] = v })
    let body: number[] | null = null
    if (init.body != null) {
      body = typeof init.body === 'string' ? Utils.toArray(init.body, 'utf8') : Array.from(init.body as Uint8Array)
    }
    captured.push({ url, method: init.method, headers, body: body == null ? null : Utils.toUTF8(body) })
    if (url.endsWith('/.well-known/auth')) {
      const request = JSON.parse(Utils.toUTF8(body!))
      const clientNonce = request.initialNonce
      const { signature } = await swiftWallet.createSignature({
        data: [...Utils.toArray(clientNonce, 'base64'), ...Utils.toArray(serverNonce, 'base64')],
        protocolID: [2, 'auth message signature'],
        keyID: `${clientNonce} ${serverNonce}`,
        counterparty: request.identityKey
      })
      const response = {
        version: '0.1', messageType: 'initialResponse', identityKey: S, nonce: serverNonce,
        initialNonce: serverNonce, yourNonce: clientNonce, signature
      }
      return new Response(JSON.stringify(response), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    throw new Error('captured')
  }
  const client = new AuthFetch(tsWallet, undefined, undefined, undefined, {}, fetchMock as any)
  try { await client.fetch('https://swift.example/a', { method: 'GET' }) } catch (e) { out.getError = String(e) }
  out.authFetch = captured

  // AuthFetch request serialization vectors (clients/AuthFetch.ts:784-818).
  const id = fill(0x07, 32)
  const ser = async (method: string, headers: Record<string, string>, body: any, url: string) =>
    Utils.toHex((await (client as any).serializeRequest(method, headers, body, new URL(url), id)).toArray())
  out.serialized = {
    getNoBody: await ser('GET', {}, undefined, 'https://h.example/a'),
    postJsonDefault: await ser('POST', { 'content-type': 'application/json' }, undefined, 'https://h.example/v1/items'),
    postEmptyString: await ser('POST', { 'content-type': 'application/json' }, '', 'https://h.example/v1/items'),
    contentTypeSpaces: await ser('POST', { 'content-type': 'application/json ; charset=utf-8' }, '{"a":1}', 'https://h.example/v1/items?x=1'),
    multipart: await ser('POST', { 'content-type': 'multipart/form-data; boundary=abc123' }, 'part', 'https://h.example/upload'),
  }
}

// ---------------- Scenario 3: certificate policy in the handshake, empty requests, ordering ----------------
{
  resetRandom(3)
  // 3a. Swift initiator sends its policy in initialRequest; a TS Peer with no listener answers
  // with certificates from its wallet inside initialResponse (Peer.ts:836-849, 872).
  const certType = b64(fill(0x71, 32))
  const serial = b64(fill(0x72, 32))
  const plaintext: Record<string, string> = { Zip: '90210', age: '30', 'a-b': 'dash', a_b: 'underscore' }
  const master = await MasterCertificate.issueCertificateForSubject(
    certifierWallet, T, plaintext, certType, async () => '00'.repeat(32) + '.0', serial)
  out.handshakeCertificateFieldOrder = Object.keys(master.fields)
  class CertWallet extends ProtoWallet {
    async listCertificates () {
      return {
        totalCertificates: 1,
        certificates: [{
          type: master.type, serialNumber: master.serialNumber, subject: master.subject,
          certifier: master.certifier, revocationOutpoint: master.revocationOutpoint,
          fields: master.fields, signature: master.signature
        }]
      }
    }
    async proveCertificate (args: any) {
      return {
        keyringForVerifier: await MasterCertificate.createKeyringForVerifier(
          tsWallet, C, args.verifier, master.fields, args.fieldsToReveal, master.masterKeyring, serial)
      }
    }
  }
  const sent: any[] = []
  let onData: (m: any) => Promise<void> = async () => {}
  const transport = {
    send: async (m: any) => { sent.push(JSON.stringify(m)) },
    onData: async (cb: any) => { onData = cb }
  }
  const responder = new Peer(new CertWallet(tsKey), transport)
  await responder.ready
  const swiftPolicy = { certifiers: [C], types: { [certType]: ['Zip', 'age', 'a_b'] } }
  out.handshakePolicy = swiftPolicy
  out.handshakePlaintext = plaintext
  await onData({
    version: '0.1', messageType: 'initialRequest', identityKey: S,
    initialNonce: b64(fill(0x41, 48)), requestedCertificates: swiftPolicy
  })
  out.initialResponseWithCertificates = sent.shift()
  out.leftover3a = sent.length

  // 3b. TS initiator; Swift responder nonce is 48 bytes of 0x61. After the handshake the TS
  // peer sends a certificateRequest with no certifiers (Peer.ts:430-490).
  const sent2: any[] = []
  let onData2: (m: any) => Promise<void> = async () => {}
  const serverNonce = b64(fill(0x61, 48))
  const transport2 = {
    send: async (m: any) => {
      sent2.push(JSON.stringify(m))
      if (m.messageType === 'initialRequest') {
        const { signature } = await swiftWallet.createSignature({
          data: [...Utils.toArray(m.initialNonce, 'base64'), ...Utils.toArray(serverNonce, 'base64')],
          protocolID: [2, 'auth message signature'],
          keyID: `${m.initialNonce} ${serverNonce}`,
          counterparty: T
        })
        void onData2({
          version: '0.1', messageType: 'initialResponse', identityKey: S,
          initialNonce: serverNonce, yourNonce: m.initialNonce, signature
        })
      }
    },
    onData: async (cb: any) => { onData2 = cb }
  }
  const initiator = new Peer(tsWallet, transport2)
  await initiator.ready
  await initiator.requestCertificates({ certifiers: [], types: {} }, S)
  out.emptyRequestInitialRequest = sent2.shift()
  out.emptyCertificateRequest = sent2.shift()
  out.leftover3b = sent2.length

  // 3c. A certificate signed by Certificate.sign with mixed-case and punctuated field names.
  const cert = new Certificate(
    b64(fill(0x81, 32)), b64(fill(0x82, 32)), T, C, '00'.repeat(32) + '.0',
    { Zip: b64([1]), age: b64([2]), 'a-b': b64([3]), a_b: b64([4]), Email: b64([5]), email: b64([6]) })
  await cert.sign(certifierWallet)
  out.mixedCaseCertificate = JSON.stringify({
    type: cert.type, serialNumber: cert.serialNumber, subject: cert.subject, certifier: cert.certifier,
    revocationOutpoint: cert.revocationOutpoint, fields: cert.fields, signature: cert.signature
  })
  out.mixedCaseCertificatePreimage = Utils.toHex(cert.toBinary(false))
  out.mixedCaseCertificateVerifies = await cert.verify()

  // 3d. Signed header order in AuthFetch.serializeRequest (AuthFetch.ts:740).
  const client = new AuthFetch(tsWallet)
  out.serializedHeaderOrder = Utils.toHex((await (client as any).serializeRequest('POST', {
    'x-bsv-zeta': '1', 'x-bsv-ab': '2', 'x-bsv-a-b': '3', 'x-bsv-a_b': '4', 'x-bsv-a.b': '5',
    'X-BSV-Upper': '6', 'content-type': 'application/json'
  }, '{}', new URL('https://h.example/h'), fill(0x07, 32))).toArray())
}

// ---------------- Scenario 4: Swift server policy answered by a TS AuthFetch client ----------------
{
  resetRandom(4)
  const certType = b64(fill(0x91, 32))
  const serial = b64(fill(0x92, 32))
  const plaintext: Record<string, string> = { Zip: '73301', age: '41', name: 'Bob' }
  const master = await MasterCertificate.issueCertificateForSubject(
    certifierWallet, T, plaintext, certType, async () => '00'.repeat(32) + '.0', serial)
  class CertWallet extends ProtoWallet {
    async listCertificates () {
      return {
        totalCertificates: 1,
        certificates: [{
          type: master.type, serialNumber: master.serialNumber, subject: master.subject,
          certifier: master.certifier, revocationOutpoint: master.revocationOutpoint,
          fields: master.fields, signature: master.signature
        }]
      }
    }
    async proveCertificate (args: any) {
      return {
        keyringForVerifier: await MasterCertificate.createKeyringForVerifier(
          tsWallet, C, args.verifier, master.fields, args.fieldsToReveal, master.masterKeyring, serial)
      }
    }
  }
  const serverPolicy = { certifiers: [C], types: { [certType]: ['Zip', 'age'] } }
  out.serverPolicy = serverPolicy
  out.serverPolicyPlaintext = plaintext
  const serverNonce = b64(fill(0x61, 48))
  const captured: any[] = []
  const fetchMock = async (url: string, init: any) => {
    const headers: Record<string, string> = {}
    new Headers(init.headers).forEach((v, k) => { headers[k] = v })
    let body: number[] | null = null
    if (init.body != null) {
      body = typeof init.body === 'string' ? Utils.toArray(init.body, 'utf8') : Array.from(init.body as Uint8Array)
    }
    captured.push({ url, method: init.method, headers, body: body == null ? null : Utils.toUTF8(body) })
    if (url.endsWith('/.well-known/auth')) {
      const request = JSON.parse(Utils.toUTF8(body!))
      if (request.messageType !== 'initialRequest') return new Response(null, { status: 204 })
      const clientNonce = request.initialNonce
      const { signature } = await swiftWallet.createSignature({
        data: [...Utils.toArray(clientNonce, 'base64'), ...Utils.toArray(serverNonce, 'base64')],
        protocolID: [2, 'auth message signature'],
        keyID: `${clientNonce} ${serverNonce}`,
        counterparty: request.identityKey
      })
      const response = {
        version: '0.1', messageType: 'initialResponse', identityKey: S, nonce: serverNonce,
        initialNonce: serverNonce, yourNonce: clientNonce, signature, requestedCertificates: serverPolicy
      }
      out.serverPolicyInitialResponse = JSON.stringify(response)
      return new Response(JSON.stringify(response), { status: 200, headers: { 'content-type': 'application/json' } })
    }
    throw new Error('captured')
  }
  const client = new AuthFetch(new CertWallet(tsKey), undefined, undefined, undefined, {}, fetchMock as any)
  try { await client.fetch('https://swift.example/b', { method: 'GET' }) } catch (e) { out.policyGetError = String(e) }
  out.policyAuthFetch = captured
}

console.log(JSON.stringify(out, null, 1))
```

## `verify.ts`

```ts
// Feeds the messages the Swift SDK wrote (BSV_TS_INTEROP_DUMP) to a live
// @bsv/sdk 4.1.1 Peer and AuthFetch, in the sessions gen.ts recorded.
import { resetRandom } from './det.ts'
const { PrivateKey, ProtoWallet, Peer, AuthFetch, Utils } = await import(`${process.env.TS_SDK}/mod.ts`)
import { readFileSync } from 'node:fs'

const dump = JSON.parse(readFileSync(process.argv[2], 'utf8'))
const vectors = JSON.parse(readFileSync(process.argv[3], 'utf8'))
const b64 = (bytes: number[]) => Utils.toBase64(bytes)
const fill = (v: number, n: number) => new Array(n).fill(v)
const tsWallet = new ProtoWallet(new PrivateKey(3))
const S = new PrivateKey(7).toPublicKey().toString()
const C = new PrivateKey(11).toPublicKey().toString()
const check = (ok: boolean, what: string) => { if (!ok) throw new Error('FAILED: ' + what); console.log('ok   ' + what) }

{
  resetRandom(1)
  const sent: string[] = []
  let onData: (m: any) => Promise<void> = async () => {}
  const transport = { send: async (m: any) => { sent.push(JSON.stringify(m)) }, onData: async (cb: any) => { onData = cb } }
  const handshakeType = b64(fill(0x51, 32))
  const peer = new Peer(tsWallet, transport, { certifiers: [C], types: { [handshakeType]: ['email'] } })
  await peer.ready
  await onData({ version: '0.1', messageType: 'initialRequest', identityKey: S, initialNonce: b64(fill(0x41, 48)) })
  check(sent.shift() === vectors.initialResponse, 'Peer replays the recorded initialResponse')

  const received: any = {}
  peer.listenForCertificatesReceived(async (sender: string, certs: any[]) => {
    received.certificates = await Promise.all(certs.map(async c => ({ type: c.type, fields: await c.decryptFields(tsWallet) })))
    received.sender = sender
  })
  peer.listenForCertificatesRequested(async (sender: string, request: any) => { received.request = request })
  peer.listenForGeneralMessages(async (sender: string, payload: number[]) => { received.general = Utils.toUTF8(payload) })

  await onData(JSON.parse(dump.clientCertificateResponse))
  check(received.sender === S, 'Peer verifies the Swift certificateResponse signature')
  check(received.certificates?.length === 1 && received.certificates[0].type === handshakeType &&
    JSON.stringify(received.certificates[0].fields) === JSON.stringify({ email: 'swift@example.test' }),
  'Peer validates the Swift certificate and decrypts the revealed field')
  await onData(JSON.parse(dump.clientCertificateRequest))
  check(received.request != null && Object.keys(received.request.types).length === 3,
    'Peer verifies the Swift certificateRequest signature')
  await onData(JSON.parse(dump.clientGeneral))
  check(received.general === 'hello from swift', 'Peer delivers the Swift general message')
  check(sent.length === 0, 'Peer sent nothing else')
}

{
  resetRandom(2)
  let request: any
  const fetchMock = async (url: string, init: any) => {
    if (url.endsWith('/.well-known/auth')) {
      return new Response(dump.serverInitialResponse, { status: 200, headers: { 'content-type': 'application/json' } })
    }
    const headers: Record<string, string> = {}
    new Headers(init.headers).forEach((v, k) => { headers[k] = v })
    request = { url, headers }
    return new Response(null, { status: dump.serverResponse.status, headers: dump.serverResponse.headers })
  }
  const client = new AuthFetch(tsWallet, undefined, undefined, undefined, {}, fetchMock as any)
  const response = await client.fetch('https://swift.example/a', { method: 'GET' })
  check(JSON.stringify(request.headers) === JSON.stringify(vectors.authFetch[1].headers),
    'AuthFetch accepts the Swift initialResponse and replays the recorded GET')
  check(response.status === 204 && (await response.text()) === '',
    'AuthFetch verifies the Swift server 204 response with an empty body')
}
console.log('all Swift messages accepted by @bsv/sdk 4.1.1')
```

## `toswift.py`

```python
import json, sys
v=json.load(open(sys.argv[1]))
def raw(s):
    assert '"#' not in s
    return '#"' + s + '"#'
get=v['authFetch'][1]
assert get['body'] is None and len(get['headers'])==6
hs=sorted(get['headers'].items())
L=[]
L.append('// Vectors produced by running the `@bsv/sdk` 4.1.1 source (ts-stack origin/main')
L.append('// 3b1abc569) with the generator in Documentation/Compatibility/TypeScriptAuthVectors.md.')
L.append('// Keys are the scalars 3 (TypeScript peer), 7 (Swift peer) and 11 (certifier). Strings are')
L.append('// the exact `JSON.stringify` wire text the TypeScript transports send. Do not edit by hand.')
L.append('enum TypeScriptAuthVectors {')
L.append(f'    static let typeScriptIdentity = "{v["tsIdentity"]}"')
L.append(f'    static let swiftIdentity = "{v["swiftIdentity"]}"')
L.append(f'    static let certifier = "{v["certifier"]}"')
L.append('')
L.append('    /// `Peer.processInitialRequest` answering a Swift initialRequest whose nonce is 48 bytes of')
L.append('    /// 0x41, with a handshake certificate policy (`Peer.ts:866-875`).')
L.append(f'    static let initialResponse =\n        {raw(v["initialResponse"])}')
L.append('')
L.append('    /// `Peer.sendCertificateResponse` (`Peer.ts:1129-1171`) answering the Swift request for')
L.append('    /// `certificateFields`. Fields are in issue order, the keyring in reveal order.')
L.append(f'    static let certificateResponse =\n        {raw(v["certificateResponse"])}')
L.append('')
L.append('    /// `Peer.requestCertificates` (`Peer.ts:430-490`) with types inserted 0x02… then 0x01….')
L.append(f'    static let certificateRequest =\n        {raw(v["certificateRequest"])}')
L.append('')
L.append('    /// The certificate type the Swift peer requested and its plaintext fields.')
L.append('    static let certificateType = [UInt8](repeating: 0x61, count: 32)')
L.append('    static let certificateFields: [(name: String, value: String)] = [')
for k,val in v['certificatePlaintext'].items():
    L.append(f'        ({json.dumps(k)}, {json.dumps(val)}),')
L.append('    ]')
L.append('')
L.append('    /// `SimplifiedFetchTransport` handshake body sent by `AuthFetch` to a server whose session')
L.append('    /// nonce is 48 bytes of 0x61.')
L.append(f'    static let authFetchInitialRequest =\n        {raw(v["authFetch"][0]["body"])}')
L.append('')
L.append('    /// The HTTP request `AuthFetch.fetch(url, { method: "GET" })` then sends for')
L.append('    /// `https://swift.example/a` (`SimplifiedFetchTransport.ts:189-194`).')
L.append(f'    static let authFetchMethod = "{get["method"]}"')
L.append('    static let authFetchPath = "/a"')
L.append('    static let authFetchHeaders: [(name: String, value: String)] = [')
for k,val in hs:
    L.append(f'        ("{k}", "{val}"),')
L.append('    ]')
L.append('')
L.append('    /// `AuthFetch.serializeRequest` (`clients/AuthFetch.ts:784-818`) with request ID 32×0x07.')
for k,val in v['serialized'].items():
    L.append(f'    static let serialized{k[0].upper()+k[1:]} =\n        "{val}"')

L.append('')
L.append('    /// `Peer.processInitialRequest` with no listener answering a Swift initialRequest (nonce')
L.append('    /// 48 bytes of 0x41) that carries `handshakePolicy`: the wallet\'s certificate is included')
L.append('    /// in initialResponse (`Peer.ts:836-849`, `Peer.ts:872`). The certificate was issued by')
L.append('    /// `MasterCertificate.issueCertificateForSubject` with `handshakeFields` in this order.')
L.append(f'    static let initialResponseWithCertificates =\n        {raw(v["initialResponseWithCertificates"])}')
L.append('    static let handshakeCertificateType = [UInt8](repeating: 0x71, count: 32)')
L.append('    static let handshakeRequestedFields = [' + ', '.join(json.dumps(f) for f in list(v['handshakePolicy']['types'].values())[0]) + ']')
L.append('    static let handshakeFields: [(name: String, value: String)] = [')
for k,val in v['handshakePlaintext'].items():
    L.append(f'        ({json.dumps(k)}, {json.dumps(val)}),')
L.append('    ]')
L.append('')
L.append('    /// A TS `Peer` initiator\'s initialRequest to a Swift responder whose nonce is 48 bytes of')
L.append('    /// 0x61, then `Peer.requestCertificates({ certifiers: [], types: {} })`.')
L.append(f'    static let emptyRequestInitialRequest =\n        {raw(v["emptyRequestInitialRequest"])}')
L.append(f'    static let emptyCertificateRequest =\n        {raw(v["emptyCertificateRequest"])}')
L.append('')
L.append('    /// A certificate signed by `Certificate.sign` (`Certificate.ts:464-485`) with field names')
L.append('    /// that `localeCompare` and byte order sort differently, and its unsigned binary')
L.append('    /// (`Certificate.ts:290`).')
L.append(f'    static let mixedCaseCertificate =\n        {raw(v["mixedCaseCertificate"])}')
L.append(f'    static let mixedCaseCertificatePreimage =\n        "{v["mixedCaseCertificatePreimage"]}"')
L.append('')
L.append('    /// `AuthFetch.serializeRequest` with headers sorted by `localeCompare` (`AuthFetch.ts:740`).')
L.append(f'    static let serializedHeaderOrder =\n        "{v["serializedHeaderOrder"]}"')
pf=v['policyAuthFetch']
assert len(pf)==3 and pf[2]['body'] is None and len(pf[2]['headers'])==6
L.append('')
L.append('    /// A TS `AuthFetch` client whose wallet holds a certificate, against a Swift server')
L.append('    /// (nonce 48 bytes of 0x61) whose policy is `serverPolicyFields` of')
L.append('    /// `serverPolicyCertificateType`: its handshake body, the initialResponse the server')
L.append('    /// was expected to send, the certificateResponse `AuthFetch` then posted on its own')
L.append('    /// (`clients/AuthFetch.ts:496-511`), and the headers of the GET it sent next.')
L.append(f'    static let policyInitialRequest =\n        {raw(pf[0]["body"])}')
L.append(f'    static let policyInitialResponse =\n        {raw(v["serverPolicyInitialResponse"])}')
L.append(f'    static let policyCertificateResponse =\n        {raw(pf[1]["body"])}')
L.append('    static let policyGetPath = "/b"')
L.append('    static let policyGetHeaders: [(name: String, value: String)] = [')
for k,val in sorted(pf[2]['headers'].items()):
    L.append(f'        ("{k}", "{val}"),')
L.append('    ]')
L.append('    static let serverPolicyCertificateType = [UInt8](repeating: 0x91, count: 32)')
L.append('    static let serverPolicyFields = [' + ', '.join(json.dumps(f) for f in list(v['serverPolicy']['types'].values())[0]) + ']')
L.append('    static let serverPolicyPlaintext: [(name: String, value: String)] = [')
for k,val in v['serverPolicyPlaintext'].items():
    L.append(f'        ({json.dumps(k)}, {json.dumps(val)}),')
L.append('    ]')
L.append('}')
open(sys.argv[2],'w').write('\n'.join(L)+'\n')
```

## `collate-vec.ts`

```ts
import { createHash } from 'node:crypto'
const cmp = (a: string, b: string) => a.localeCompare(b)
const hash = (xs: string[]) => createHash('sha256').update(xs.join('\n'), 'utf8').digest('hex')
const printable: string[] = []
for (let c = 0x20; c <= 0x7e; c++) printable.push(String.fromCharCode(c))
console.log('ascii', JSON.stringify([...printable].sort(cmp).join('')))
const pairs: string[] = []
let ties = 0
for (const a of printable) for (const b of printable) pairs.push(a + b)
for (let i = 0; i < pairs.length; i++) for (let j = i + 1; j < pairs.length; j++) if (cmp(pairs[i], pairs[j]) === 0) ties++
console.log('pairs', pairs.length, 'ties', ties, hash([...pairs].sort(cmp)))
const alpha = ' !-._09aAzZ'
const triples: string[] = []
for (const a of alpha) for (const b of alpha) for (const c of alpha) triples.push(a + b + c)
console.log('triples', triples.length, hash([...triples].sort(cmp)))
// LCG strings, length 1..8 over printable ASCII
let x = 1
const next = () => { x = (Math.imul(x, 1103515245) + 12345) >>> 0 & 0x7fffffff; return x }
const randoms: string[] = []
for (let i = 0; i < 4000; i++) {
  const len = 1 + (next() % 8)
  let s = ''
  for (let k = 0; k < len; k++) s += printable[next() % 95]
  randoms.push(s)
}
const uniq = [...new Set(randoms)]
let rties = 0
const rs = [...uniq].sort(cmp)
for (let i = 0; i + 1 < rs.length; i++) if (cmp(rs[i], rs[i + 1]) === 0) rties++
console.log('randoms', uniq.length, 'adjacent ties', rties, hash(rs), JSON.stringify(randoms.slice(0, 3)))
console.log('names', JSON.stringify(['Zip', 'age', 'a_b', 'a-b', 'ab', 'a b', 'A', 'a', 'aB', 'Ab', 'a1', 'a10', 'a2', 'x-bsv-a_b', 'x-bsv-ab', 'x-bsv-a-b', 'x-bsv-Z', 'x-bsv-z', 'email', 'Email', 'first_name', 'firstName', 'first-name'].sort(cmp)))
console.log('headers', JSON.stringify(['x-bsv-zeta', 'x-bsv-a-b', 'x-bsv-a_b', 'x-bsv-ab', 'x-bsv-a.b', 'x-bsv-a1', 'authorization', 'content-type'].sort(cmp)))
console.log(process.versions.bun, Intl.Collator().resolvedOptions().locale)
```
