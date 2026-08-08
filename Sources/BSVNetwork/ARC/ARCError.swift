import BSVCore

/// Why an ARC submission outcome cannot be known locally.
public enum ARCUncertainDeliveryCause: Hashable, Sendable {
    case cancelled
    case timedOut
    case transport(code: Int?)
    case redirect(statusCode: Int)
    case responseBodyTooLarge(maximumByteCount: Int)
    case providerResponse(httpStatusCode: Int, status: Int?)
    case invalidResponse
}

/// ARC-specific semantic and submission failures.
public enum ARCError: Error, Hashable, Sendable {
    /// ARC explicitly rejected the submitted transaction.
    case rejected(httpStatusCode: Int, response: ARCResponse)

    /// HTTP or ARC payload semantics did not indicate success.
    case providerFailure(httpStatusCode: Int, response: ARCResponse)

    /// The POST may have reached ARC even though no response was received.
    /// Reconcile by transaction ID; do not blindly resubmit.
    case uncertainDelivery(
        transactionID: TransactionID,
        cause: ARCUncertainDeliveryCause
    )
}
