import BSVCore
import BSVTransaction

/// Failures from deterministic overlay lookup and topic-broadcast policy.
public enum OverlayPolicyError: Error, Equatable, Sendable {
    case noCompetentHosts
    case noSuccessfulResponses
    /// No longer thrown: output lists win over freeform answers.
    case inconsistentAnswerTypes
    case invalidLookupOutput
    case discoveryResponseNotOutputList
    case noInterestedHosts
    case invalidAtomicBEEF
    case uncertainDelivery
    case acknowledgmentFailed
    /// A host's STEAK was empty or acknowledged a topic it was not sent.
    case invalidSteak
}

/// A bounded service that resolves one overlay lookup question.
public protocol OverlayLookupResolving: Sendable {
    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer
}

/// Which advertised hosts discovery may contact.
public enum OverlayDiscoveredHostPolicy: Hashable, Sendable {
    /// Only hosts that may be public network endpoints: no loopback, private,
    /// link-local, shared, multicast or reserved address, and no `localhost`,
    /// `.local` or `.internal` name. `@bsv/sdk` applies the same address rules
    /// to every request through `createPublicNetworkFetch`
    /// (`storage/PublicHTTPSFetch.ts:114-158`). This is the default, because
    /// anyone can publish a one-satoshi advertisement.
    case publicNetworkOnly
    /// Any `https://` origin, for private deployments and tests.
    case anyHTTPSOrigin
}

/// A host that gave no usable answer, with the reason, for logging.
public struct OverlayHostFailure: Sendable {
    public let host: OverlayHost
    public let error: any Error

    public init(host: OverlayHost, error: any Error) {
        self.host = host
        self.error = error
    }
}

/// An output a host returned that the resolver left out, with the reason.
public struct LookupOutputRejection: Sendable {
    public let host: OverlayHost
    public let output: OutputListItem
    public let error: any Error

    public init(host: OverlayHost, output: OutputListItem, error: any Error) {
        self.host = host
        self.output = output
        self.error = error
    }
}

/// A lookup result with the hosts and outputs that were left out of it.
public struct LookupResolution: Sendable {
    /// The merged answer, or nil when no host gave a usable one.
    public let answer: LookupAnswer?
    /// Hosts whose request failed, in sorted host order.
    public let hostFailures: [OverlayHostFailure]
    /// Outputs left out because their transaction or output could not be read.
    public let rejectedOutputs: [LookupOutputRejection]
}

/// An immutable, bounded resolver for SHIP and SLAP lookup services.
///
/// The resolver has no built-in tracker, network, or transport policy. The
/// caller supplies each tracker, override, additional host, and facilitator.
/// Host order and merged output order are deterministic.
public struct LookupResolver: OverlayLookupResolving, Sendable {
    private let facilitator: any LookupFacilitator
    private let slapTrackers: [OverlayHost]
    private let hostOverrides: [OverlayService: [OverlayHost]]
    private let additionalHosts: [OverlayService: [OverlayHost]]
    private let beefLimits: BEEFLimits
    private let adminTokenLimits: OverlayAdminTokenLimits
    private let discoveredHostPolicy: OverlayDiscoveredHostPolicy
    private let limits: OverlayLimits

    /// Hosts given here that are `https://` origins are normalized as
    /// discovered hosts are (lowercase host, no default port, no trailing
    /// slash), so one origin is queried once. Two spellings of one origin in
    /// the same list are a duplicate, as in `@bsv/sdk` (`LookupResolver.ts:551-568`).
    /// Other hosts are used as given. `discoveredHostPolicy` applies only to
    /// hosts found through SLAP advertisements.
    public init(
        facilitator: any LookupFacilitator,
        slapTrackers: [OverlayHost],
        hostOverrides: [OverlayService: [OverlayHost]] = [:],
        additionalHosts: [OverlayService: [OverlayHost]] = [:],
        beefLimits: BEEFLimits,
        adminTokenLimits: OverlayAdminTokenLimits = .standard,
        discoveredHostPolicy: OverlayDiscoveredHostPolicy = .publicNetworkOnly,
        limits: OverlayLimits = .standard
    ) throws {
        let trackers = Self.normalized(slapTrackers, limits: limits)
        let overrides = hostOverrides.mapValues { Self.normalized($0, limits: limits) }
        let additional = additionalHosts.mapValues { Self.normalized($0, limits: limits) }
        try Self.validateHosts(trackers, limits: limits)
        for hosts in overrides.values {
            try Self.validateHosts(hosts, limits: limits)
        }
        for hosts in additional.values {
            try Self.validateHosts(hosts, limits: limits)
        }
        self.facilitator = facilitator
        self.slapTrackers = trackers.sorted()
        self.hostOverrides = overrides.mapValues { $0.sorted() }
        self.additionalHosts = additional.mapValues { $0.sorted() }
        self.beefLimits = beefLimits
        self.adminTokenLimits = adminTokenLimits
        self.discoveredHostPolicy = discoveredHostPolicy
        self.limits = limits
    }

    /// Resolves `question` and returns the merged answer.
    ///
    /// Throws ``OverlayPolicyError/noSuccessfulResponses`` when no host
    /// answered, and ``OverlayPolicyError/invalidLookupOutput`` when hosts
    /// answered only with outputs that could not be read. Use
    /// ``resolveDetailed(_:)`` to see which hosts failed and why.
    public func resolve(_ question: LookupQuestion) async throws -> LookupAnswer {
        let resolution = try await resolveDetailed(question)
        guard let answer = resolution.answer else {
            throw resolution.rejectedOutputs.isEmpty
                ? OverlayPolicyError.noSuccessfulResponses
                : OverlayPolicyError.invalidLookupOutput
        }
        return answer
    }

    /// Resolves `question` and reports each failed host and each output left
    /// out, with its reason.
    ///
    /// As in `@bsv/sdk`, one host's bad output does not fail the lookup: an
    /// output whose transaction cannot be read from its BEEF, whose `txid`
    /// disagrees with its BEEF, or whose index is out of range is left out
    /// (`resolveTxIdForOutput` in `LookupResolver.ts`). The answer is nil when
    /// no host answered, or when every output any host returned was left out.
    public func resolveDetailed(_ question: LookupQuestion) async throws -> LookupResolution {
        let hosts = try await competentHosts(for: question.service)
        guard !hosts.isEmpty else { throw OverlayPolicyError.noCompetentHosts }
        let results = try await query(question, at: hosts)
        var answers: [(OverlayHost, LookupAnswer)] = []
        var failures: [OverlayHostFailure] = []
        for (host, result) in results {
            switch result {
            case .success(let answer): answers.append((host, answer))
            case .failure(let error): failures.append(OverlayHostFailure(host: host, error: error))
            }
        }
        let (answer, rejected) = try aggregate(answers)
        return LookupResolution(answer: answer, hostFailures: failures, rejectedOutputs: rejected)
    }

    /// Returns the explicit or discovered hosts for one lookup service.
    public func competentHosts(for service: OverlayService) async throws -> [OverlayHost] {
        let primary: [OverlayHost]
        if service.rawValue == "ls_slap" {
            primary = slapTrackers
        } else if let override = hostOverrides[service] {
            primary = override
        } else {
            primary = try await discoverHosts(for: service)
        }
        let combined = Self.uniqueSorted(primary + (additionalHosts[service] ?? []))
        try Self.validateHosts(combined, limits: limits)
        return combined
    }

    private func discoverHosts(for service: OverlayService) async throws -> [OverlayHost] {
        guard !slapTrackers.isEmpty else { return [] }
        let slapService: OverlayService
        do {
            slapService = try OverlayService(rawValue: "ls_slap", limits: limits)
        } catch {
            throw OverlayPolicyError.noCompetentHosts
        }
        let queryBytes = Array("{\"service\":\"\(service.rawValue)\"}".utf8)
        let question = try LookupQuestion(
            service: slapService,
            query: queryBytes,
            limits: limits
        )
        let results = try await query(question, at: slapTrackers)
        guard results.contains(where: { if case .success = $0.1 { true } else { false } }) else {
            throw OverlayPolicyError.noSuccessfulResponses
        }
        var discovered: Set<OverlayHost> = []
        for case (_, .success(.outputList(let outputs))) in results {
            for output in outputs {
                guard
                    let token = verifiedAdvertisement(
                        in: output,
                        beefLimits: beefLimits,
                        adminTokenLimits: adminTokenLimits
                    ),
                    token.subject == .slap(service),
                    let host = advertisedHTTPSHost(
                        token, policy: discoveredHostPolicy, limits: limits)
                else { continue }
                discovered.insert(host)
                guard discovered.count <= limits.maximumResolutionHostCount else {
                    throw OverlayError.limitExceeded(
                        name: "resolvedHosts",
                        actual: discovered.count,
                        maximum: limits.maximumResolutionHostCount
                    )
                }
            }
        }
        return discovered.sorted()
    }

    /// Each host's answer or failure, in host order. Only cancellation and
    /// host-count limits throw.
    private func query(
        _ question: LookupQuestion,
        at hosts: [OverlayHost]
    ) async throws -> [(OverlayHost, Result<LookupAnswer, any Error>)] {
        try Self.validateHosts(hosts, limits: limits)
        var indexed: [(Int, Result<LookupAnswer, any Error>)] = []
        let width = limits.maximumConcurrentRequestCount
        var start = 0
        while start < hosts.count {
            try Task.checkCancellation()
            let end = min(hosts.count, start + width)
            try await withThrowingTaskGroup(
                of: (Int, Result<LookupAnswer, any Error>).self
            ) { group in
                for index in start..<end {
                    let host = hosts[index]
                    group.addTask {
                        try Task.checkCancellation()
                        do {
                            let answer = try await facilitator.lookup(
                                question: question,
                                at: host
                            )
                            try Task.checkCancellation()
                            return (index, .success(answer))
                        } catch is CancellationError {
                            throw CancellationError()
                        } catch {
                            return (index, .failure(error))
                        }
                    }
                }
                for try await result in group {
                    indexed.append(result)
                }
            }
            start = end
        }
        try Task.checkCancellation()
        return indexed.sorted { $0.0 < $1.0 }.map { (hosts[$0.0], $0.1) }
    }

    /// Merges the hosts' answers.
    ///
    /// When any host answers with an output list, the result is the merged
    /// output lists and freeform answers are left out, as `@bsv/sdk`
    /// `LookupResolver.query` does (`LookupResolver.ts:1508-1528`). When every
    /// answering host answers freeform, the first freeform answer in sorted
    /// host order is returned.
    private func aggregate(
        _ answers: [(OverlayHost, LookupAnswer)]
    ) throws -> (LookupAnswer?, [LookupOutputRejection]) {
        let hasOutputs = answers.contains { if case .outputList = $0.1 { true } else { false } }
        if !hasOutputs {
            guard case .freeform(let bytes)? = answers.first?.1 else { return (nil, []) }
            return (try LookupAnswer(freeform: bytes, limits: limits), [])
        }

        var outputsByKey: [OverlayOutputKey: OutputListItem] = [:]
        var rejected: [LookupOutputRejection] = []
        var outputCount = 0
        for case (let host, .outputList(let outputs)) in answers {
            outputCount += outputs.count
            for output in outputs {
                let key: OverlayOutputKey
                do {
                    key = try outputKey(for: output)
                } catch {
                    rejected.append(LookupOutputRejection(host: host, output: output, error: error))
                    continue
                }
                if outputsByKey[key] == nil {
                    outputsByKey[key] = output
                }
            }
        }
        if outputCount > 0, outputsByKey.isEmpty { return (nil, rejected) }
        let outputs = outputsByKey.keys.sorted().compactMap { outputsByKey[$0] }
        return (try LookupAnswer(outputList: outputs, limits: limits), rejected)
    }

    private func outputKey(for output: OutputListItem) throws -> OverlayOutputKey {
        let transaction = try output.transaction(beefLimits: beefLimits)
        guard Int(output.outputIndex) < transaction.outputs.count else {
            throw OverlayPolicyError.invalidLookupOutput
        }
        let transactionID = try transaction.transactionID(limits: beefLimits.transactionLimits)
        return OverlayOutputKey(transactionID: transactionID, outputIndex: output.outputIndex)
    }

    private static func normalized(_ hosts: [OverlayHost], limits: OverlayLimits) -> [OverlayHost] {
        hosts.map { host in
            OverlayAdvertisementURI.httpsOrigin(host.rawValue)
                .flatMap { try? OverlayHost(rawValue: $0, limits: limits) } ?? host
        }
    }

    private static func validateHosts(
        _ hosts: [OverlayHost],
        limits: OverlayLimits
    ) throws {
        guard hosts.count <= limits.maximumResolutionHostCount else {
            throw OverlayError.limitExceeded(
                name: "resolvedHosts",
                actual: hosts.count,
                maximum: limits.maximumResolutionHostCount
            )
        }
        guard Set(hosts).count == hosts.count else {
            throw OverlayError.duplicateValue(name: "hosts")
        }
    }

    private static func uniqueSorted(_ hosts: [OverlayHost]) -> [OverlayHost] {
        Array(Set(hosts)).sorted()
    }
}

extension OutputListItem {
    /// The transaction that holds this output.
    ///
    /// With a ``transactionID`` the output names its transaction, which is
    /// taken from the BEEF; an Atomic BEEF must have it as its subject.
    /// Without one, an Atomic BEEF gives its subject and a standard BEEF gives
    /// its last transaction once reordered parents-first.
    ///
    /// Throws the BEEF decoding error when `beef` cannot be read, and
    /// ``OverlayPolicyError/invalidLookupOutput`` when the BEEF lacks the
    /// named transaction or names another subject.
    public func transaction(beefLimits: BEEFLimits) throws -> Transaction {
        if beef.count >= 4, beef[0] == 1, beef[1] == 1, beef[2] == 1, beef[3] == 1 {
            let atomic = try AtomicBEEF(bytes: beef, limits: beefLimits, transactionOrder: .any)
            if let named = transactionID, named != atomic.subjectTransactionID {
                throw OverlayPolicyError.invalidLookupOutput
            }
            guard
                let transaction = try atomic.beef.transaction(
                    for: atomic.subjectTransactionID,
                    limits: beefLimits.transactionLimits
                )
            else { throw OverlayPolicyError.invalidLookupOutput }
            return transaction
        }
        let standard = try BEEF(bytes: beef, limits: beefLimits, transactionOrder: .any)
        if let named = transactionID {
            guard
                let transaction = try standard.transaction(
                    for: named,
                    limits: beefLimits.transactionLimits
                )
            else { throw OverlayPolicyError.invalidLookupOutput }
            return transaction
        }
        // Lookup answers come from `@bsv/sdk` writers, which can list a child
        // before its parents. Reordered parents-first, `last` is a transaction no
        // other record spends, not whichever record the writer emitted last.
        // `Transaction.fromBEEF` in `@bsv/sdk` takes the record last on the wire
        // instead; the two differ only when the writer put a parent last. This
        // keeps the reordered choice: a transaction nothing else in the answer
        // spends.
        guard let transaction = standard.transactions.last?.transaction else {
            throw OverlayPolicyError.invalidLookupOutput
        }
        return transaction
    }
}

/// ``OutputListItem/transaction(beefLimits:)`` with every failure reported as
/// ``OverlayPolicyError/invalidLookupOutput``.
package func overlayLookupTransaction(
    for output: OutputListItem,
    beefLimits: BEEFLimits
) throws -> Transaction {
    do {
        return try output.transaction(beefLimits: beefLimits)
    } catch let error as OverlayPolicyError {
        throw error
    } catch {
        throw OverlayPolicyError.invalidLookupOutput
    }
}

/// The verified SHIP or SLAP advertisement a discovery output holds, or nil.
///
/// As in `@bsv/sdk` (`LookupResolver.ts:2210-2232`, `SHIPBroadcaster.ts:755-777`),
/// the output must hold exactly one satoshi and a token that passes
/// ``OverlayAdminTokenCodec/decode(_:limits:)``.
package func verifiedAdvertisement(
    in output: OutputListItem,
    beefLimits: BEEFLimits,
    adminTokenLimits: OverlayAdminTokenLimits
) -> OverlayAdminToken? {
    guard let transaction = try? output.transaction(beefLimits: beefLimits),
        Int(output.outputIndex) < transaction.outputs.count
    else { return nil }
    let selected = transaction.outputs[Int(output.outputIndex)]
    guard selected.satoshis == 1 else { return nil }
    return try? OverlayAdminTokenCodec.decode(selected.lockingScript, limits: adminTokenLimits)
}

/// The `https://` origin an advertisement names, as a host the HTTPS
/// facilitators accept, or nil when it names another transport or a host
/// `policy` excludes.
package func advertisedHTTPSHost(
    _ token: OverlayAdminToken,
    policy: OverlayDiscoveredHostPolicy,
    limits: OverlayLimits
) -> OverlayHost? {
    let uri = token.host.rawValue
    guard let origin = OverlayAdvertisementURI.httpsOrigin(uri) else { return nil }
    if policy == .publicNetworkOnly, !OverlayAdvertisementURI.isPublicHTTPSOrigin(uri) {
        return nil
    }
    return try? OverlayHost(rawValue: origin, limits: limits)
}

private struct OverlayOutputKey: Hashable, Comparable, Sendable {
    let transactionID: TransactionID
    let outputIndex: UInt32

    static func < (lhs: Self, rhs: Self) -> Bool {
        if lhs.transactionID.displayHex != rhs.transactionID.displayHex {
            return lhs.transactionID.displayHex < rhs.transactionID.displayHex
        }
        return lhs.outputIndex < rhs.outputIndex
    }
}
