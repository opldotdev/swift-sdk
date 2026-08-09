import BSVCore
import BSVTransaction

/// Failures from deterministic overlay lookup and topic-broadcast policy.
public enum OverlayPolicyError: Error, Equatable, Sendable {
    case noCompetentHosts
    case noSuccessfulResponses
    case inconsistentAnswerTypes
    case invalidLookupOutput
    case discoveryResponseNotOutputList
    case noInterestedHosts
    case invalidAtomicBEEF
    case uncertainDelivery
    case acknowledgmentFailed
}

/// A bounded service that resolves one overlay lookup question.
public protocol OverlayLookupResolving: Sendable {
    func resolve(_ question: LookupQuestion) async throws -> LookupAnswer
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
    private let limits: OverlayLimits

    public init(
        facilitator: any LookupFacilitator,
        slapTrackers: [OverlayHost],
        hostOverrides: [OverlayService: [OverlayHost]] = [:],
        additionalHosts: [OverlayService: [OverlayHost]] = [:],
        beefLimits: BEEFLimits,
        adminTokenLimits: OverlayAdminTokenLimits = .standard,
        limits: OverlayLimits = .standard
    ) throws {
        try Self.validateHosts(slapTrackers, limits: limits)
        for hosts in hostOverrides.values {
            try Self.validateHosts(hosts, limits: limits)
        }
        for hosts in additionalHosts.values {
            try Self.validateHosts(hosts, limits: limits)
        }
        self.facilitator = facilitator
        self.slapTrackers = Self.uniqueSorted(slapTrackers)
        self.hostOverrides = hostOverrides.mapValues(Self.uniqueSorted)
        self.additionalHosts = additionalHosts.mapValues(Self.uniqueSorted)
        self.beefLimits = beefLimits
        self.adminTokenLimits = adminTokenLimits
        self.limits = limits
    }

    public func resolve(_ question: LookupQuestion) async throws -> LookupAnswer {
        let hosts = try await competentHosts(for: question.service)
        guard !hosts.isEmpty else { throw OverlayPolicyError.noCompetentHosts }
        let responses = try await query(question, at: hosts)
        return try aggregate(responses)
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
        let responses = try await query(question, at: slapTrackers)
        var discovered: Set<OverlayHost> = []
        for response in responses {
            guard case .outputList(let outputs) = response else { continue }
            for output in outputs {
                guard
                    let transaction = try? overlayLookupTransaction(
                        for: output,
                        beefLimits: beefLimits
                    ),
                    Int(output.outputIndex) < transaction.outputs.count,
                    let token = try? OverlayAdminTokenCodec.decode(
                        transaction.outputs[Int(output.outputIndex)].lockingScript,
                        limits: adminTokenLimits
                    ),
                    token.subject == .slap(service)
                else { continue }
                discovered.insert(token.host)
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

    private func query(
        _ question: LookupQuestion,
        at hosts: [OverlayHost]
    ) async throws -> [LookupAnswer] {
        try Self.validateHosts(hosts, limits: limits)
        var indexed: [(Int, LookupAnswer)] = []
        let width = limits.maximumConcurrentRequestCount
        var start = 0
        while start < hosts.count {
            try Task.checkCancellation()
            let end = min(hosts.count, start + width)
            try await withThrowingTaskGroup(of: (Int, LookupAnswer?).self) { group in
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
                            return (index, answer)
                        } catch is CancellationError {
                            throw CancellationError()
                        } catch {
                            return (index, nil)
                        }
                    }
                }
                for try await result in group {
                    if let answer = result.1 {
                        indexed.append((result.0, answer))
                    }
                }
            }
            start = end
        }
        try Task.checkCancellation()
        guard !indexed.isEmpty else { throw OverlayPolicyError.noSuccessfulResponses }
        return indexed.sorted { $0.0 < $1.0 }.map(\.1)
    }

    private func aggregate(_ responses: [LookupAnswer]) throws -> LookupAnswer {
        let hasFreeform = responses.contains { if case .freeform = $0 { true } else { false } }
        let hasOutputs = responses.contains { if case .outputList = $0 { true } else { false } }
        guard !(hasFreeform && hasOutputs) else {
            throw OverlayPolicyError.inconsistentAnswerTypes
        }
        if hasFreeform {
            guard case .freeform(let bytes) = responses[0] else {
                throw OverlayPolicyError.inconsistentAnswerTypes
            }
            return try LookupAnswer(freeform: bytes, limits: limits)
        }

        var outputsByKey: [OverlayOutputKey: OutputListItem] = [:]
        for response in responses {
            guard case .outputList(let outputs) = response else {
                throw OverlayPolicyError.inconsistentAnswerTypes
            }
            for output in outputs {
                let key = try outputKey(for: output)
                if outputsByKey[key] == nil {
                    outputsByKey[key] = output
                }
            }
        }
        let outputs = outputsByKey.keys.sorted().compactMap { outputsByKey[$0] }
        return try LookupAnswer(outputList: outputs, limits: limits)
    }

    private func outputKey(for output: OutputListItem) throws -> OverlayOutputKey {
        let transaction = try overlayLookupTransaction(for: output, beefLimits: beefLimits)
        guard Int(output.outputIndex) < transaction.outputs.count else {
            throw OverlayPolicyError.invalidLookupOutput
        }
        let transactionID = try transaction.transactionID(limits: beefLimits.transactionLimits)
        return OverlayOutputKey(transactionID: transactionID, outputIndex: output.outputIndex)
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

package func overlayLookupTransaction(
    for output: OutputListItem,
    beefLimits: BEEFLimits
) throws -> Transaction {
    do {
        if output.beef.count >= 4,
            output.beef[0] == 1,
            output.beef[1] == 1,
            output.beef[2] == 1,
            output.beef[3] == 1
        {
            let atomic = try AtomicBEEF(bytes: output.beef, limits: beefLimits)
            guard
                let transaction = try atomic.beef.transaction(
                    for: atomic.subjectTransactionID,
                    limits: beefLimits.transactionLimits
                )
            else {
                throw OverlayPolicyError.invalidLookupOutput
            }
            return transaction
        }
        let beef = try BEEF(bytes: output.beef, limits: beefLimits)
        guard let transaction = beef.transactions.last?.transaction else {
            throw OverlayPolicyError.invalidLookupOutput
        }
        return transaction
    } catch let error as OverlayPolicyError {
        throw error
    } catch {
        throw OverlayPolicyError.invalidLookupOutput
    }
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
