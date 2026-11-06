import Foundation

/// Where a pattern has to appear in the base64 part of a `SHA256:` fingerprint.
public enum MatchPosition: String, CaseIterable, Sendable {
  case prefix
  case suffix
  case contains
}

/// Reasons a pattern can never match a fingerprint.
public enum PatternError: Error, Equatable, CustomStringConvertible {
  case empty
  case tooLong(Int)
  case invalidCharacter(Character)
  case impossibleLastCharacter(Character)

  public var description: String {
    switch self {
    case .empty:
      return "The pattern is empty."
    case .tooLong(let length):
      return "The pattern has \(length) characters; a fingerprint has only "
        + "\(Pattern.fingerprintLength)."
    case .invalidCharacter(let character):
      return "'\(character)' never appears in a fingerprint. Use A-Z, a-z, 0-9, + and /."
    case .impossibleLastCharacter(let character):
      return "A fingerprint can't end with '\(character)': its last character is one of "
        + "\(String(Pattern.lastCharacters))."
    }
  }
}

/// A pattern compiled into per-character masks of allowed base64 values.
public struct Pattern: Equatable, Sendable {
  /// The standard base64 alphabet; a character's index is its 6-bit value.
  public static let alphabet = Array(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")

  /// Length of an unpadded base64 SHA-256 digest.
  public static let fingerprintLength = 43

  /// The 43rd character encodes only 4 digest bits followed by two zero bits,
  /// so only values that are multiples of 4 can appear there.
  static let lastCharacterMask: UInt64 = (0..<16).reduce(0) { $0 | 1 << UInt64($1 * 4) }

  static var lastCharacters: [Character] {
    alphabet.indices.filter { lastCharacterMask >> UInt64($0) & 1 == 1 }.map { alphabet[$0] }
  }

  public let text: String
  public let position: MatchPosition
  public let caseSensitive: Bool

  /// `masks[i]` has bit `v` set when base64 value `v` matches character `i`.
  public let masks: [UInt64]

  /// Fingerprint positions the pattern may start at, inclusive.
  public let starts: ClosedRange<Int>

  public init(
    _ text: String, position: MatchPosition = .prefix, caseSensitive: Bool = false
  ) throws {
    let characters = Array(text)
    guard !characters.isEmpty else { throw PatternError.empty }
    guard characters.count <= Self.fingerprintLength else {
      throw PatternError.tooLong(characters.count)
    }
    var masks: [UInt64] = []
    for character in characters {
      var mask: UInt64 = 0
      for (value, candidate) in Self.alphabet.enumerated() {
        let same =
          caseSensitive
          ? candidate == character
          : candidate.lowercased() == character.lowercased()
        if same { mask |= 1 << UInt64(value) }
      }
      guard mask != 0 else { throw PatternError.invalidCharacter(character) }
      masks.append(mask)
    }

    let lastStart = Self.fingerprintLength - characters.count
    switch position {
    case .prefix: starts = 0...0
    case .suffix: starts = lastStart...lastStart
    case .contains: starts = 0...lastStart
    }
    self.text = text
    self.position = position
    self.caseSensitive = caseSensitive
    self.masks = masks

    guard probability > 0 else {
      throw PatternError.impossibleLastCharacter(characters[characters.count - 1])
    }
  }

  /// Chance that one random key matches.
  public var probability: Double {
    let hits = starts.map { start in
      masks.enumerated().reduce(1.0) { hit, element in
        let isLast = start + element.offset == Self.fingerprintLength - 1
        let allowed = isLast ? element.element & Self.lastCharacterMask : element.element
        return hit * Double(allowed.nonzeroBitCount) / (isLast ? 16 : 64)
      }
    }
    guard hits.count > 1 else { return hits[0] }
    // 1 - prod(1 - hit), via logarithms so that tiny chances don't round to 0.
    return -expm1(hits.reduce(0) { $0 + log1p(-$1) })
  }

  /// Mean number of keys to try before a match.
  public var expectedAttempts: Double { 1 / probability }

  /// Checks a fingerprint, given without the `SHA256:` prefix.
  public func matches(_ fingerprint: String) -> Bool {
    let values = fingerprint.compactMap { Self.alphabet.firstIndex(of: $0) }
    guard values.count == Self.fingerprintLength else { return false }
    return starts.contains { start in
      masks.enumerated().allSatisfy { offset, mask in
        mask >> UInt64(values[start + offset]) & 1 == 1
      }
    }
  }
}
