/// Stable failures from the SDK's bounded arbitrary-precision adapter.
package enum BigNumError: Error, Equatable, Sendable {
    case invalidLimit(Int)
    case inputTooLarge(actual: Int, maximum: Int)
    case resultTooLarge(estimated: Int, maximum: Int)
    case operationBudgetExceeded(actual: Int, maximum: Int)
    case invalidShift(Int)
    case subtractionUnderflow
    case divisionByZero
    case invalidModulus
    case notInvertible
    case nativeIntegerOverflow
}
