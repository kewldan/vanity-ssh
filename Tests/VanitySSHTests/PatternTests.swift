import Foundation
import Testing

@testable import VanitySSH

@Suite struct PatternTests {
  @Test func caseInsensitiveLettersMatchBothCases() throws {
    let pattern = try Pattern("kewl")
    #expect(pattern.masks.map(\.nonzeroBitCount) == [2, 2, 2, 2])
    #expect(pattern.expectedAttempts == Double(1 << 20))
  }

  @Test func caseSensitiveLettersMatchOneCase() throws {
    let pattern = try Pattern("kewl", caseSensitive: true)
    #expect(pattern.masks.map(\.nonzeroBitCount) == [1, 1, 1, 1])
    #expect(pattern.expectedAttempts == Double(1 << 24))
  }

  @Test func digitsAndSymbolsHaveOneValue() throws {
    let pattern = try Pattern("a1+/")
    #expect(pattern.masks.map(\.nonzeroBitCount) == [2, 1, 1, 1])
  }

  @Test(arguments: ["", "kewl-dan", "ключ", String(repeating: "a", count: 44)])
  func rejectsImpossiblePatterns(text: String) {
    #expect(throws: PatternError.self) { try Pattern(text) }
  }

  @Test func suffixMustEndWithAPossibleLastCharacter() throws {
    #expect(throws: PatternError.impossibleLastCharacter("n")) {
      try Pattern("dan", position: .suffix)
    }
    // "o" (value 40) can end a fingerprint; "O" (value 14) can't.
    let pattern = try Pattern("dano", position: .suffix)
    #expect(pattern.starts == 39...39)
    #expect(pattern.expectedAttempts == 32 * 32 * 32 * 16)
  }

  @Test func containsTriesEveryStart() throws {
    let pattern = try Pattern("kewl", position: .contains)
    #expect(pattern.starts == 0...39)
    // Start 39 can't match: "l" can't be the last fingerprint character.
    #expect(abs(pattern.expectedAttempts - Double(1 << 20) / 39) < 1)
  }

  @Test func keepsTinyProbabilities() throws {
    let pattern = try Pattern(String(repeating: "A", count: 43), caseSensitive: true)
    #expect(pattern.probability == pow(2, -256))
  }

  @Test func matchesFingerprints() throws {
    let fingerprint = "KewLdAnP2lTK+DNRYI1e7+oe7Vwabjg9LKKlGL3mf2U"
    #expect(try Pattern("kewldan").matches(fingerprint))
    #expect(try !Pattern("kewldan", caseSensitive: true).matches(fingerprint))
    #expect(try Pattern("KewLdAn", caseSensitive: true).matches(fingerprint))
    #expect(try Pattern("mf2u", position: .suffix).matches(fingerprint))
    #expect(try Pattern("+dnr", position: .contains).matches(fingerprint))
    #expect(try !Pattern("+dnr").matches(fingerprint))
  }
}
