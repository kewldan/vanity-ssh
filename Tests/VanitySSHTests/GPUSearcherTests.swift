import CryptoKit
import Metal
import Testing

@testable import VanitySSH

/// Checks the GPU against CryptoKit, an independent Ed25519 implementation.
/// Skipped on machines without a Metal GPU.
@Suite(.enabled(if: MTLCreateSystemDefaultDevice() != nil, "needs a Metal GPU"))
struct GPUSearcherTests {
  @Test(arguments: [8, 16])
  func digestsMatchCryptoKit(windowBits: Int) throws {
    var options = GPUSearchOptions()
    options.windowBits = windowBits
    let searcher = try GPUSearcher(options: options)
    let base = (0..<32).map { _ in UInt8.random(in: 0...255) }
    let count = 4096
    let digests = try searcher.digests(base: base, count: count)
    for index in 0..<count {
      let key = try Ed25519Key(seed: GPUSearcher.seed(base: base, index: UInt32(index)))
      let expected = Array(SHA256.hash(data: key.publicKeyBlob))
      try #require(digests[index] == expected, "key \(index)")
    }
  }

  @Test(arguments: [
    ("ab", MatchPosition.prefix),
    ("kA", MatchPosition.suffix),
    ("xyz", MatchPosition.contains),
  ])
  func findsMatchingKeys(text: String, position: MatchPosition) throws {
    var options = GPUSearchOptions()
    options.windowBits = 8
    options.threadsPerBatch = 1 << 12
    let searcher = try GPUSearcher(options: options)
    let pattern = try Pattern(text, position: position)
    let key = try #require(try searcher.search(pattern: pattern))
    #expect(pattern.matches(key.fingerprint))
  }

  @Test func stopsWhenAsked() throws {
    var options = GPUSearchOptions()
    options.windowBits = 8
    options.threadsPerBatch = 1 << 10
    let searcher = try GPUSearcher(options: options)
    let pattern = try Pattern(String(repeating: "A", count: 43), caseSensitive: true)
    var batches = 0
    let key = try searcher.search(pattern: pattern) { _ in
      batches += 1
      return batches < 3
    }
    #expect(key == nil)
    #expect(batches == 3)
  }
}
