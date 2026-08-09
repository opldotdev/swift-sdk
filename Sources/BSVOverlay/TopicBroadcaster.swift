import BSVCore
import BSVTransaction

/// A deterministic, one-shot SHIP broadcaster for caller-supplied Atomic BEEF.
///
/// This broadcaster has no default resolver, tracker, transport, or retry. It
/// discovers signed SHIP advertisements through the injected resolver and
/// submits to each interested host at most once.
public struct OverlayTopicBroadcaster: Sendable {
    private let topics: [OverlayTopic]
    private let facilitator: any TopicFacilitator
    private let resolver: any OverlayLookupResolving
    private let acknowledgmentFromEveryHost: AckFrom
    private let acknowledgmentFromAnyHost: AckFrom
    private let acknowledgmentByHost: [OverlayHost: AckFrom]
    private let beefLimits: BEEFLimits
    private let adminTokenLimits: OverlayAdminTokenLimits
    private let limits: OverlayLimits

    public init(
        topics: [OverlayTopic],
        facilitator: any TopicFacilitator,
        resolver: any OverlayLookupResolving,
        acknowledgmentFromEveryHost: AckFrom? = nil,
        acknowledgmentFromAnyHost: AckFrom? = nil,
        acknowledgmentByHost: [OverlayHost: AckFrom] = [:],
        beefLimits: BEEFLimits,
        adminTokenLimits: OverlayAdminTokenLimits = .standard,
        limits: OverlayLimits = .standard
    ) throws {
        guard !topics.isEmpty else { throw OverlayError.emptyValue(name: "topics") }
        guard topics.count <= limits.maximumTopicCount else {
            throw OverlayError.limitExceeded(
                name: "topics",
                actual: topics.count,
                maximum: limits.maximumTopicCount
            )
        }
        guard Set(topics).count == topics.count else {
            throw OverlayError.duplicateValue(name: "topics")
        }
        guard acknowledgmentByHost.count <= limits.maximumResolutionHostCount else {
            throw OverlayError.limitExceeded(
                name: "acknowledgmentHosts",
                actual: acknowledgmentByHost.count,
                maximum: limits.maximumResolutionHostCount
            )
        }

        let orderedTopics = topics.sorted()
        let every =
            try acknowledgmentFromEveryHost
            ?? AckFrom(requirement: .none, limits: limits)
        let any =
            try acknowledgmentFromAnyHost
            ?? AckFrom(requirement: .all, limits: limits)
        try Self.validate(every, against: orderedTopics)
        try Self.validate(any, against: orderedTopics)
        for requirement in acknowledgmentByHost.values {
            try Self.validate(requirement, against: orderedTopics)
        }

        self.topics = orderedTopics
        self.facilitator = facilitator
        self.resolver = resolver
        self.acknowledgmentFromEveryHost = every
        self.acknowledgmentFromAnyHost = any
        self.acknowledgmentByHost = acknowledgmentByHost
        self.beefLimits = beefLimits
        self.adminTokenLimits = adminTokenLimits
        self.limits = limits
    }

    public func broadcast(
        _ atomicBEEF: AtomicBEEF,
        offChainValues: [UInt8] = []
    ) async throws -> BroadcastResult {
        try Task.checkCancellation()
        let bytes: [UInt8]
        do {
            bytes = try atomicBEEF.serialized(limits: beefLimits)
        } catch {
            throw OverlayPolicyError.invalidAtomicBEEF
        }
        let tagged = try TaggedBEEF(
            beef: bytes,
            topics: topics,
            offChainValues: offChainValues,
            limits: limits
        )
        let hosts = try await interestedHosts()
        guard !hosts.isEmpty else { throw OverlayPolicyError.noInterestedHosts }
        let results = try await submit(tagged, to: hosts)
        try validateAcknowledgments(results)
        return BroadcastResult(
            transactionID: atomicBEEF.subjectTransactionID,
            message: "Submitted to \(results.count) overlay host(s)."
        )
    }

    private func interestedHosts() async throws -> [OverlayHost] {
        let service: OverlayService
        do {
            service = try OverlayService(rawValue: "ls_ship", limits: limits)
        } catch {
            throw OverlayPolicyError.noInterestedHosts
        }
        let topicJSON = topics.map { "\"\($0.rawValue)\"" }.joined(separator: ",")
        let question = try LookupQuestion(
            service: service,
            query: Array("{\"topics\":[\(topicJSON)]}".utf8),
            limits: limits
        )
        let answer = try await resolver.resolve(question)
        guard case .outputList(let outputs) = answer else {
            throw OverlayPolicyError.discoveryResponseNotOutputList
        }

        let requested = Set(topics)
        var hosts: Set<OverlayHost> = []
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
                case .ship(let topic) = token.subject,
                requested.contains(topic)
            else { continue }
            hosts.insert(token.host)
            guard hosts.count <= limits.maximumResolutionHostCount else {
                throw OverlayError.limitExceeded(
                    name: "interestedHosts",
                    actual: hosts.count,
                    maximum: limits.maximumResolutionHostCount
                )
            }
        }
        return hosts.sorted()
    }

    private func submit(
        _ taggedBEEF: TaggedBEEF,
        to hosts: [OverlayHost]
    ) async throws -> [OverlayHost: Steak] {
        var indexed: [(Int, OverlayHost, Steak)] = []
        var uncertain = false
        let width = limits.maximumConcurrentRequestCount
        var start = 0
        while start < hosts.count {
            try Task.checkCancellation()
            let end = min(hosts.count, start + width)
            await withTaskGroup(of: OverlaySubmissionOutcome.self) { group in
                for index in start..<end {
                    let host = hosts[index]
                    group.addTask {
                        do {
                            try Task.checkCancellation()
                            let steak = try await facilitator.submit(taggedBEEF, to: host)
                            try Task.checkCancellation()
                            return .success(index, host, steak)
                        } catch {
                            return .uncertain
                        }
                    }
                }
                for await result in group {
                    switch result {
                    case .success(let index, let host, let steak):
                        indexed.append((index, host, steak))
                    case .uncertain:
                        uncertain = true
                    }
                }
            }
            start = end
        }
        if uncertain || Task.isCancelled {
            throw OverlayPolicyError.uncertainDelivery
        }
        guard indexed.count == hosts.count else {
            throw OverlayPolicyError.uncertainDelivery
        }
        return Dictionary(
            uniqueKeysWithValues: indexed.sorted { $0.0 < $1.0 }.map { ($0.1, $0.2) }
        )
    }

    private func validateAcknowledgments(_ results: [OverlayHost: Steak]) throws {
        let ordered = results.keys.sorted()
        if !ordered.allSatisfy({ host in
            results[host].map {
                Self.satisfies(
                    acknowledgmentFromEveryHost,
                    steak: $0,
                    allTopics: topics
                )
            } == true
        }) {
            throw OverlayPolicyError.acknowledgmentFailed
        }
        if !ordered.contains(where: { host in
            results[host].map {
                Self.satisfies(
                    acknowledgmentFromAnyHost,
                    steak: $0,
                    allTopics: topics
                )
            } == true
        }) {
            throw OverlayPolicyError.acknowledgmentFailed
        }
        for (host, requirement) in acknowledgmentByHost {
            guard let steak = results[host],
                Self.satisfies(requirement, steak: steak, allTopics: topics)
            else {
                throw OverlayPolicyError.acknowledgmentFailed
            }
        }
    }

    private static func validate(
        _ requirement: AckFrom,
        against topics: [OverlayTopic]
    ) throws {
        if requirement.requirement == .some,
            !Set(requirement.topics).isSubset(of: Set(topics))
        {
            throw OverlayError.invalidTopic
        }
    }

    private static func satisfies(
        _ requirement: AckFrom,
        steak: Steak,
        allTopics: [OverlayTopic]
    ) -> Bool {
        let acknowledged = Set(
            steak.instructions.compactMap { topic, instruction in
                instruction.acknowledgesTopic ? topic : nil
            }
        )
        switch requirement.requirement {
        case .none:
            return true
        case .any:
            return !acknowledged.isDisjoint(with: Set(allTopics))
        case .some:
            return Set(requirement.topics).isSubset(of: acknowledged)
        case .all:
            return Set(allTopics).isSubset(of: acknowledged)
        }
    }
}

private enum OverlaySubmissionOutcome: Sendable {
    case success(Int, OverlayHost, Steak)
    case uncertain
}
