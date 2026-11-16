import BSVCore
import BSVTransaction

/// What one broadcast did at each host.
public struct OverlayBroadcastReport: Sendable {
    public let transactionID: TransactionID
    /// The topics each host acknowledged, for every host that answered with
    /// a usable STEAK.
    public let acknowledgedTopics: [OverlayHost: Set<OverlayTopic>]
    /// Hosts whose submission failed, with the reason, in sorted host order.
    /// Their delivery is uncertain: a host may have admitted the transaction
    /// before its answer was lost.
    public let hostFailures: [OverlayHostFailure]
    /// Why the broadcast did not meet its acknowledgment requirements, or nil
    /// when it did.
    public let failure: OverlayPolicyError?
    /// Advertised hosts left out because the host limit was reached. Hosts
    /// named in the acknowledgment requirements always keep their places, so
    /// a caller that must reach every advertised host can treat a nonzero
    /// count as a partial broadcast.
    public let skippedHostCount: Int
}

/// A deterministic, one-shot SHIP broadcaster for caller-supplied Atomic BEEF.
///
/// This broadcaster has no default resolver, tracker, transport, or retry. It
/// discovers signed SHIP advertisements through the injected resolver and
/// submits to each interested host at most once, naming only the topics that
/// host advertised.
///
/// Acknowledgment requirements follow `@bsv/sdk` `SHIPBroadcaster`
/// (`SHIPBroadcaster.ts:466-545`). By default some host must acknowledge every
/// topic, and other hosts may fail: one bogus advertisement does not fail every
/// broadcast. A failed host counts as acknowledging nothing, so a requirement
/// on every host or on a named host fails when that host fails. Requirements
/// are checked against all of the broadcast's topics.
public struct OverlayTopicBroadcaster: Sendable {
    private let topics: [OverlayTopic]
    private let facilitator: any TopicFacilitator
    private let resolver: any OverlayLookupResolving
    private let acknowledgmentFromEveryHost: AckFrom
    private let acknowledgmentFromAnyHost: AckFrom
    private let acknowledgmentByHost: [OverlayHost: AckFrom]
    private let beefLimits: BEEFLimits
    private let adminTokenLimits: OverlayAdminTokenLimits
    private let discoveredHostPolicy: OverlayDiscoveredHostPolicy
    private let limits: OverlayLimits

    /// `acknowledgmentByHost` keys must be `https://` origins, the only hosts
    /// discovery yields; `https://host/` and `https://host` name one host.
    public init(
        topics: [OverlayTopic],
        facilitator: any TopicFacilitator,
        resolver: any OverlayLookupResolving,
        acknowledgmentFromEveryHost: AckFrom? = nil,
        acknowledgmentFromAnyHost: AckFrom? = nil,
        acknowledgmentByHost: [OverlayHost: AckFrom] = [:],
        beefLimits: BEEFLimits,
        adminTokenLimits: OverlayAdminTokenLimits = .standard,
        discoveredHostPolicy: OverlayDiscoveredHostPolicy = .publicNetworkOnly,
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
        // Discovered hosts are `https://` origins, so a requirement keyed by
        // `https://host/` names the same host as `https://host`, and a key
        // that is not an origin could never match: `@bsv/sdk` rejects it
        // (`snapshotSpecificHostRequirements`).
        var requirementsByHost: [OverlayHost: AckFrom] = [:]
        for (host, requirement) in acknowledgmentByHost {
            try Self.validate(requirement, against: orderedTopics)
            guard let origin = OverlayAdvertisementURI.httpsOrigin(host.rawValue) else {
                throw OverlayError.invalidHost
            }
            let key = try OverlayHost(rawValue: origin, limits: limits)
            guard requirementsByHost.updateValue(requirement, forKey: key) == nil else {
                throw OverlayError.duplicateValue(name: "acknowledgmentHosts")
            }
        }

        self.topics = orderedTopics
        self.facilitator = facilitator
        self.resolver = resolver
        self.acknowledgmentFromEveryHost = every
        self.acknowledgmentFromAnyHost = any
        self.acknowledgmentByHost = requirementsByHost
        self.beefLimits = beefLimits
        self.adminTokenLimits = adminTokenLimits
        self.discoveredHostPolicy = discoveredHostPolicy
        self.limits = limits
    }

    /// Broadcasts and throws when the acknowledgment requirements are not met.
    ///
    /// Throws ``OverlayPolicyError/acknowledgmentFailed`` when every host
    /// answered and the requirements are not met, and
    /// ``OverlayPolicyError/uncertainDelivery`` when they are not met and a
    /// host failed, since that host may have admitted the transaction. Use
    /// ``broadcastDetailed(_:offChainValues:)`` to see each host's outcome.
    public func broadcast(
        _ atomicBEEF: AtomicBEEF,
        offChainValues: [UInt8] = []
    ) async throws -> BroadcastResult {
        let report = try await broadcastDetailed(atomicBEEF, offChainValues: offChainValues)
        if let failure = report.failure { throw failure }
        let failed = report.hostFailures.count
        return BroadcastResult(
            transactionID: report.transactionID,
            message: failed == 0
                ? "Submitted to \(report.acknowledgedTopics.count) overlay host(s)."
                : "Submitted to \(report.acknowledgedTopics.count) overlay host(s); "
                    + "\(failed) failed."
        )
    }

    /// Broadcasts and reports each host's outcome. Throws only before any
    /// submission (invalid input, discovery failure, no interested host) or on
    /// cancellation; requirement failures are in ``OverlayBroadcastReport/failure``.
    public func broadcastDetailed(
        _ atomicBEEF: AtomicBEEF,
        offChainValues: [UInt8] = []
    ) async throws -> OverlayBroadcastReport {
        try Task.checkCancellation()
        let bytes: [UInt8]
        do {
            bytes = try atomicBEEF.serialized(limits: beefLimits)
        } catch {
            throw OverlayPolicyError.invalidAtomicBEEF
        }
        // Check the payload against the limits before any network request.
        _ = try TaggedBEEF(
            beef: bytes,
            topics: topics,
            offChainValues: offChainValues,
            limits: limits
        )
        let (hosts, skippedHostCount) = try await interestedHosts()
        guard !hosts.isEmpty else { throw OverlayPolicyError.noInterestedHosts }
        var submissions: [(OverlayHost, TaggedBEEF)] = []
        submissions.reserveCapacity(hosts.count)
        for (host, hostTopics) in hosts.sorted(by: { $0.key < $1.key }) {
            submissions.append(
                (
                    host,
                    try TaggedBEEF(
                        beef: bytes,
                        topics: hostTopics.sorted(),
                        offChainValues: offChainValues,
                        limits: limits
                    )
                )
            )
        }
        let outcomes = try await submit(submissions)
        var acknowledged: [OverlayHost: Set<OverlayTopic>] = [:]
        var failures: [OverlayHostFailure] = []
        for (host, outcome) in outcomes {
            switch outcome {
            case .success(let steak): acknowledged[host] = Self.acknowledgedTopics(in: steak)
            case .failure(let error): failures.append(OverlayHostFailure(host: host, error: error))
            }
        }
        for hostFailure in failures {
            OverlayLog.hostFailure("OverlayTopicBroadcaster.broadcast", hostFailure)
        }
        var failure: OverlayPolicyError?
        if !requirementsMet(acknowledged, hosts: hosts.keys) {
            failure = failures.isEmpty ? .acknowledgmentFailed : .uncertainDelivery
        }
        return OverlayBroadcastReport(
            transactionID: atomicBEEF.subjectTransactionID,
            acknowledgedTopics: acknowledged,
            hostFailures: failures,
            failure: failure,
            skippedHostCount: skippedHostCount
        )
    }

    /// Each interested host and the broadcast topics it advertised.
    ///
    /// Like `@bsv/sdk` `SHIPBroadcaster` (`SHIPBroadcaster.ts:476-482,738-783`),
    /// each host is later sent only the topics it advertised, because the
    /// overlay engine refuses a submission that names a topic it does not host.
    /// As there, hosts past the host limit are left out and counted rather
    /// than failing the broadcast. Hosts named in `acknowledgmentByHost` keep
    /// their places, so advertisements cannot crowd out a host the caller
    /// requires; other hosts fill the rest in the resolver's output order.
    private func interestedHosts() async throws -> (
        hosts: [OverlayHost: Set<OverlayTopic>], skipped: Int
    ) {
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
        var hosts: [OverlayHost: Set<OverlayTopic>] = [:]
        let unnamedRoom = limits.maximumResolutionHostCount - acknowledgmentByHost.count
        var unnamedCount = 0
        var skipped = 0
        for output in outputs {
            guard
                let token = verifiedAdvertisement(
                    in: output,
                    beefLimits: beefLimits,
                    adminTokenLimits: adminTokenLimits,
                    operation: "OverlayTopicBroadcaster.broadcast"
                ),
                case .ship(let topic) = token.subject,
                requested.contains(topic),
                let host = advertisedHTTPSHost(
                    token, policy: discoveredHostPolicy, limits: limits)
            else { continue }
            if hosts[host] == nil, acknowledgmentByHost[host] == nil {
                guard unnamedCount < unnamedRoom else {
                    skipped += 1
                    continue
                }
                unnamedCount += 1
            }
            hosts[host, default: []].insert(topic)
        }
        if skipped > 0 {
            OverlayLog.skippedHosts(
                "OverlayTopicBroadcaster.broadcast", count: skipped,
                limit: limits.maximumResolutionHostCount)
        }
        return (hosts, skipped)
    }

    /// Each host's STEAK or failure, in host order. A host that answers with
    /// an empty STEAK, or acknowledges a topic it was not sent, has failed, as
    /// in `@bsv/sdk` (`SHIPBroadcaster.ts:476-496`).
    private func submit(
        _ submissions: [(OverlayHost, TaggedBEEF)]
    ) async throws -> [(OverlayHost, Result<Steak, any Error>)] {
        var indexed: [(Int, Result<Steak, any Error>)] = []
        let width = limits.maximumConcurrentRequestCount
        var start = 0
        while start < submissions.count {
            if Task.isCancelled {
                if start == 0 { throw CancellationError() }
                throw OverlayPolicyError.uncertainDelivery
            }
            let end = min(submissions.count, start + width)
            await withTaskGroup(of: (Int, Result<Steak, any Error>).self) { group in
                for index in start..<end {
                    let (host, taggedBEEF) = submissions[index]
                    group.addTask {
                        do {
                            try Task.checkCancellation()
                            let steak = try await facilitator.submit(taggedBEEF, to: host)
                            try Task.checkCancellation()
                            guard !steak.instructions.isEmpty,
                                Set(steak.instructions.keys).isSubset(of: taggedBEEF.topics)
                            else { return (index, .failure(OverlayPolicyError.invalidSteak)) }
                            return (index, .success(steak))
                        } catch {
                            return (index, .failure(error))
                        }
                    }
                }
                for await result in group {
                    indexed.append(result)
                }
            }
            start = end
        }
        // A submission may have reached a host before cancellation, so its
        // delivery is uncertain rather than cancelled.
        if Task.isCancelled { throw OverlayPolicyError.uncertainDelivery }
        return indexed.sorted { $0.0 < $1.0 }.map { (submissions[$0.0].0, $0.1) }
    }

    private func requirementsMet(
        _ acknowledged: [OverlayHost: Set<OverlayTopic>],
        hosts: Dictionary<OverlayHost, Set<OverlayTopic>>.Keys
    ) -> Bool {
        let none: Set<OverlayTopic> = []
        guard !acknowledged.isEmpty else { return false }
        guard
            hosts.allSatisfy({
                Self.satisfies(acknowledgmentFromEveryHost, acknowledged[$0] ?? none, topics)
            })
        else { return false }
        guard
            acknowledged.values.contains(where: {
                Self.satisfies(acknowledgmentFromAnyHost, $0, topics)
            })
        else { return false }
        // A named host that discovery did not return fails even a `.none`
        // requirement, as in `@bsv/sdk` (`SHIPBroadcaster.ts:659-662`).
        for (host, requirement) in acknowledgmentByHost {
            guard hosts.contains(host),
                Self.satisfies(requirement, acknowledged[host] ?? none, topics)
            else {
                return false
            }
        }
        return true
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

    private static func acknowledgedTopics(in steak: Steak) -> Set<OverlayTopic> {
        Set(
            steak.instructions.compactMap { topic, instruction in
                instruction.acknowledgesTopic ? topic : nil
            }
        )
    }

    private static func satisfies(
        _ requirement: AckFrom,
        _ acknowledged: Set<OverlayTopic>,
        _ allTopics: [OverlayTopic]
    ) -> Bool {
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
