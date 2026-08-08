import BSVCore
import BSVCrypto
import BSVKeys
import Foundation

/// Stable validation and derivation failures for an English BIP-39 mnemonic.
public enum MnemonicError: Error, Equatable, Sendable {
    /// BIP-39 accepts 128, 160, 192, 224, or 256 bits of entropy.
    case invalidEntropyByteCount(Int)
    /// BIP-39 accepts 12, 15, 18, 21, or 24 words.
    case invalidWordCount(Int)
    /// The normalized phrase contains a word outside the English BIP-39 list.
    case unknownWord(String)
    /// The mnemonic's checksum bits do not match its recovered entropy.
    case checksumMismatch
    /// Whitespace appeared outside words or more than once between two words.
    case malformedPhrase
    /// The fixed BIP-39 seed derivation failed in the cryptographic backend.
    case seedDerivationFailed
}

/// A validated English BIP-39 mnemonic for backup and import workflows.
///
/// BIP-39 remains useful for mnemonic recovery. BRC-42 protocol-key derivation
/// does not replace mnemonic backup and import.
///
/// Phrase input is normalized with Unicode NFKD. Exactly one Unicode whitespace
/// character is accepted between words; leading, trailing, or repeated
/// whitespace is rejected. Input and normalized UTF-8 are each limited to 4,096
/// bytes, and parsing stops after 24 words or eight scalars in a word. Output
/// always uses one ASCII space.
public struct Mnemonic: Hashable, Sendable, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable {
    private static let allowedEntropyByteCounts: Set<Int> = [16, 20, 24, 28, 32]
    private static let allowedWordCounts: Set<Int> = [12, 15, 18, 21, 24]
    private static let maximumPhraseUTF8ByteCount = 4_096
    private static let maximumNormalizedWordScalarCount = 8

    /// The canonical English words in stable BIP-39 order. This is recovery secret material.
    public let words: [String]

    /// The entropy recovered from the words, without checksum bits. This is secret material.
    public let entropy: [UInt8]

    /// The canonical mnemonic separated by single ASCII spaces.
    ///
    /// Reading this property intentionally exports recovery secret material.
    public var phrase: String {
        words.joined(separator: " ")
    }

    /// A redacted description suitable for interpolation and diagnostic logging.
    /// Use ``phrase`` only when intentionally exporting the recovery secret.
    public var description: String { "<redacted mnemonic>" }

    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(reflecting: description) }

    /// Creates the exact English BIP-39 mnemonic for supported entropy.
    public init(entropy: [UInt8]) throws {
        guard Self.allowedEntropyByteCounts.contains(entropy.count) else {
            throw MnemonicError.invalidEntropyByteCount(entropy.count)
        }

        let checksumBitCount = entropy.count / 4
        let checksum = BSVHashing.sha256(entropy).bytes[0]
        let wordCount = (entropy.count * 8 + checksumBitCount) / 11
        var words: [String] = []
        words.reserveCapacity(wordCount)

        for wordOffset in 0..<wordCount {
            var index = 0
            for bitInWord in 0..<11 {
                let bitOffset = wordOffset * 11 + bitInWord
                let bit: UInt8
                if bitOffset < entropy.count * 8 {
                    let byte = entropy[bitOffset / 8]
                    bit = (byte >> (7 - bitOffset % 8)) & 1
                } else {
                    let checksumOffset = bitOffset - entropy.count * 8
                    bit = (checksum >> (7 - checksumOffset)) & 1
                }
                index = (index << 1) | Int(bit)
            }
            words.append(BIP39EnglishWordList.words[index])
        }

        self.words = words
        self.entropy = entropy
    }

    /// Parses and validates a bounded English BIP-39 phrase.
    ///
    /// Both the supplied and NFKD-normalized UTF-8 representations must fit in
    /// 4,096 bytes. This cap is deliberately much larger than any canonical
    /// English BIP-39 phrase while bounding normalization and parsing work.
    public init(_ phrase: String) throws {
        guard phrase.utf8.prefix(Self.maximumPhraseUTF8ByteCount + 1).count
            <= Self.maximumPhraseUTF8ByteCount else {
            throw MnemonicError.malformedPhrase
        }
        let normalized = phrase.decomposedStringWithCompatibilityMapping
        guard normalized.utf8.prefix(Self.maximumPhraseUTF8ByteCount + 1).count
            <= Self.maximumPhraseUTF8ByteCount else {
            throw MnemonicError.malformedPhrase
        }
        let parsedWords = try Self.parseWords(normalized)
        guard Self.allowedWordCounts.contains(parsedWords.count) else {
            throw MnemonicError.invalidWordCount(parsedWords.count)
        }

        var indices: [Int] = []
        indices.reserveCapacity(parsedWords.count)
        for word in parsedWords {
            guard let index = BIP39EnglishWordList.indices[word] else {
                throw MnemonicError.unknownWord(word)
            }
            indices.append(index)
        }

        let totalBitCount = indices.count * 11
        let entropyBitCount = totalBitCount * 32 / 33
        let entropyByteCount = entropyBitCount / 8
        let checksumBitCount = totalBitCount - entropyBitCount
        var entropy = [UInt8](repeating: 0, count: entropyByteCount)

        for bitOffset in 0..<entropyBitCount {
            let index = indices[bitOffset / 11]
            let bit = UInt8((index >> (10 - bitOffset % 11)) & 1)
            entropy[bitOffset / 8] |= bit << (7 - bitOffset % 8)
        }

        var suppliedChecksum: UInt8 = 0
        for checksumOffset in 0..<checksumBitCount {
            let bitOffset = entropyBitCount + checksumOffset
            let index = indices[bitOffset / 11]
            let bit = UInt8((index >> (10 - bitOffset % 11)) & 1)
            suppliedChecksum = (suppliedChecksum << 1) | bit
        }
        let expectedChecksum = BSVHashing.sha256(entropy).bytes[0] >> (8 - checksumBitCount)
        guard suppliedChecksum == expectedChecksum else {
            throw MnemonicError.checksumMismatch
        }

        self.words = parsedWords
        self.entropy = entropy
    }

    /// Derives the BIP-39 seed with NFKD normalization and the fixed
    /// PBKDF2-HMAC-SHA512 profile (2,048 rounds, 64 output bytes).
    public func seed(passphrase: String = "") throws -> Hash512 {
        let normalizedMnemonic = phrase.decomposedStringWithCompatibilityMapping
        let normalizedPassphrase = passphrase.decomposedStringWithCompatibilityMapping
        let salt = "mnemonic" + normalizedPassphrase

        do {
            let bytes = try BIP39PBKDF2.deriveSeed(
                mnemonicUTF8: Array(normalizedMnemonic.utf8),
                saltUTF8: Array(salt.utf8)
            )
            return Hash512(exactDigestBytesGuaranteed: bytes)
        } catch {
            throw MnemonicError.seedDerivationFailed
        }
    }

    private static func parseWords(_ normalized: String) throws -> [String] {
        guard !normalized.isEmpty else {
            throw MnemonicError.invalidWordCount(0)
        }

        var words: [String] = []
        var current = ""
        var previousWasWhitespace = false
        for scalar in normalized.unicodeScalars {
            if scalar.properties.isWhitespace {
                guard !current.isEmpty, !previousWasWhitespace else {
                    throw MnemonicError.malformedPhrase
                }
                guard words.count < 24 else {
                    throw MnemonicError.invalidWordCount(words.count + 1)
                }
                words.append(current)
                current.removeAll(keepingCapacity: true)
                previousWasWhitespace = true
            } else {
                guard (0x61...0x7a).contains(scalar.value) else {
                    throw MnemonicError.malformedPhrase
                }
                guard current.unicodeScalars.count < maximumNormalizedWordScalarCount else {
                    throw MnemonicError.malformedPhrase
                }
                current.unicodeScalars.append(scalar)
                previousWasWhitespace = false
            }
        }
        guard !current.isEmpty else {
            throw MnemonicError.malformedPhrase
        }
        guard words.count < 24 else {
            throw MnemonicError.invalidWordCount(words.count + 1)
        }
        words.append(current)
        return words
    }
}
