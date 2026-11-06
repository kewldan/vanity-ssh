import Foundation
import Metal
import Security

/// Tuning knobs for the GPU search.
public struct GPUSearchOptions: Sendable {
  /// Fixed-base table window. 16 bits: 125 MB table, fastest. 8 bits: 1 MB.
  public var windowBits = 16
  /// Keys each GPU thread derives; they share one field inversion.
  public var keysPerThread = 32
  /// Threads per command buffer.
  public var threadsPerBatch = 1 << 17

  public init() {}

  /// Bytes the fixed-base table takes on the GPU.
  public var tableBytes: Int { ((256 / windowBits) << windowBits) * 30 * 4 }
}

public enum GPUSearchError: Error, CustomStringConvertible {
  case noDevice
  case badOptions(String)
  case compile(String)
  case commandFailed(String)
  case randomFailed
  case verificationFailed(String)

  public var description: String {
    switch self {
    case .noDevice: return "No Metal GPU found."
    case .badOptions(let message): return message
    case .compile(let message): return "Metal compilation failed: \(message)"
    case .commandFailed(let message): return "GPU command failed: \(message)"
    case .randomFailed: return "The system random number generator failed."
    case .verificationFailed(let fingerprint):
      return "The GPU reported SHA256:\(fingerprint), which doesn't match on the CPU. "
        + "This is a bug; please report it."
    }
  }
}

/// Progress of a running search.
public struct SearchProgress: Sendable {
  public let attempts: UInt64
  public let elapsed: TimeInterval
  public var keysPerSecond: Double { elapsed > 0 ? Double(attempts) / elapsed : 0 }
}

/// Derives Ed25519 keys from random seeds on the GPU and checks their
/// fingerprints against a pattern.
///
/// Each batch starts from a fresh 32-byte base from the system CSPRNG; key `i`
/// of a batch uses the base with `i` XORed into its first four bytes.
public final class GPUSearcher {
  public let device: MTLDevice
  public let options: GPUSearchOptions
  private let queue: MTLCommandQueue
  private let table: MTLBuffer
  private let digestsPipeline: MTLComputePipelineState
  private let searchPipeline: MTLComputePipelineState

  /// Keys tried per command buffer.
  public var keysPerBatch: Int { options.threadsPerBatch * options.keysPerThread }

  public init(options: GPUSearchOptions = GPUSearchOptions(), device: MTLDevice? = nil) throws {
    guard [8, 16].contains(options.windowBits) else {
      throw GPUSearchError.badOptions("The table window must be 8 or 16 bits.")
    }
    guard (1...64).contains(options.keysPerThread) else {
      throw GPUSearchError.badOptions("Keys per thread must be between 1 and 64.")
    }
    guard let device = device ?? MTLCreateSystemDefaultDevice() else {
      throw GPUSearchError.noDevice
    }
    guard let queue = device.makeCommandQueue() else { throw GPUSearchError.noDevice }
    self.device = device
    self.options = options
    self.queue = queue

    let compileOptions = MTLCompileOptions()
    // Pin the language version: the default depends on the binary's deployment
    // target, so tests and the release could otherwise compile different MSL.
    compileOptions.languageVersion = .version3_0
    compileOptions.preprocessorMacros = [
      "WBITS": NSNumber(value: options.windowBits),
      "KEYS_PER_THREAD": NSNumber(value: options.keysPerThread),
    ]
    let library: MTLLibrary
    do {
      library = try device.makeLibrary(source: KernelSource.text, options: compileOptions)
    } catch {
      throw GPUSearchError.compile("\(error)")
    }
    func pipeline(_ name: String) throws -> MTLComputePipelineState {
      guard let function = library.makeFunction(name: name) else {
        throw GPUSearchError.compile("missing function \(name)")
      }
      return try device.makeComputePipelineState(function: function)
    }
    digestsPipeline = try pipeline("Digests")
    searchPipeline = try pipeline("Search")

    let windows = 256 / options.windowBits
    guard
      let rows = device.makeBuffer(length: windows * 40 * 4, options: .storageModePrivate),
      let table = device.makeBuffer(length: options.tableBytes, options: .storageModePrivate)
    else {
      throw GPUSearchError.badOptions("Can't allocate the \(options.tableBytes >> 20) MB table.")
    }
    self.table = table
    try run([
      (try pipeline("RowBases"), [rows], windows),
      (try pipeline("BuildTable"), [rows, table], windows << options.windowBits),
    ])
  }

  /// Fingerprint digests (SHA-256 of the public key blob) of keys `0..<count`
  /// derived from `base`. `count` must be a multiple of `keysPerThread`.
  public func digests(base: [UInt8], count: Int) throws -> [[UInt8]] {
    precondition(base.count == 32 && count % options.keysPerThread == 0)
    guard let baseBuffer = device.makeBuffer(bytes: base, length: 32),
      let out = device.makeBuffer(length: count * 32)
    else { throw GPUSearchError.commandFailed("buffer allocation failed") }
    try run([(digestsPipeline, [baseBuffer, table, out], count / options.keysPerThread)])
    let words = out.contents().bindMemory(to: UInt32.self, capacity: count * 8)
    return (0..<count).map { key in
      (0..<8).flatMap { word in
        let value = words[key * 8 + word]
        return [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> $0) }
      }
    }
  }

  /// Seed of key `index` in a batch that started from `base`.
  public static func seed(base: [UInt8], index: UInt32) -> [UInt8] {
    var seed = base
    for byte in 0..<4 { seed[byte] ^= UInt8(truncatingIfNeeded: index >> (8 * byte)) }
    return seed
  }

  /// Searches until a key matches or `shouldContinue` returns false.
  ///
  /// `shouldContinue` runs after every batch. A match is re-checked on the CPU
  /// with CryptoKit before it is returned.
  public func search(
    pattern: Pattern, shouldContinue: (SearchProgress) -> Bool = { _ in true }
  ) throws -> Ed25519Key? {
    var params = [
      UInt32(pattern.masks.count), UInt32(pattern.starts.lowerBound),
      UInt32(pattern.starts.upperBound),
    ]
    guard
      let masks = device.makeBuffer(
        bytes: pattern.masks, length: pattern.masks.count * 8, options: .storageModeShared),
      let paramsBuffer = device.makeBuffer(bytes: &params, length: 12)
    else { throw GPUSearchError.commandFailed("buffer allocation failed") }

    struct Batch {
      let base: [UInt8]
      let result: MTLBuffer
      let commandBuffer: MTLCommandBuffer
    }
    func submit() throws -> Batch {
      let base = try Self.randomBase()
      guard let baseBuffer = device.makeBuffer(bytes: base, length: 32),
        let result = device.makeBuffer(length: 8, options: .storageModeShared)
      else { throw GPUSearchError.commandFailed("buffer allocation failed") }
      memset(result.contents(), 0, 8)
      let commandBuffer = try encode([
        (
          searchPipeline, [baseBuffer, table, masks, paramsBuffer, result],
          options.threadsPerBatch
        )
      ])
      commandBuffer.commit()
      return Batch(base: base, result: result, commandBuffer: commandBuffer)
    }

    let start = Date()
    var attempts: UInt64 = 0
    // Two batches in flight keep the GPU busy while the CPU checks results.
    var inFlight = [try submit(), try submit()]
    defer { inFlight.forEach { $0.commandBuffer.waitUntilCompleted() } }
    while true {
      let batch = inFlight.removeFirst()
      batch.commandBuffer.waitUntilCompleted()
      if let error = batch.commandBuffer.error {
        throw GPUSearchError.commandFailed("\(error)")
      }
      attempts += UInt64(keysPerBatch)
      let result = batch.result.contents().bindMemory(to: UInt32.self, capacity: 2)
      if result[0] > 0 {
        let key = try Ed25519Key(seed: Self.seed(base: batch.base, index: result[1]))
        guard pattern.matches(key.fingerprint) else {
          throw GPUSearchError.verificationFailed(key.fingerprint)
        }
        return key
      }
      let progress = SearchProgress(attempts: attempts, elapsed: Date().timeIntervalSince(start))
      guard shouldContinue(progress) else { return nil }
      inFlight.append(try submit())
    }
  }

  /// Measures throughput with a pattern that never matches.
  public func benchmark(seconds: TimeInterval) throws -> SearchProgress {
    // Matching all 43 characters has a probability of about 2^-256.
    let pattern = try Pattern(
      String(repeating: "A", count: Pattern.fingerprintLength), caseSensitive: true)
    var last = SearchProgress(attempts: 0, elapsed: 0)
    let found = try search(pattern: pattern) { progress in
      last = progress
      return progress.elapsed < seconds
    }
    precondition(found == nil, "the benchmark pattern can't realistically match")
    return last
  }

  private static func randomBase() throws -> [UInt8] {
    var bytes = [UInt8](repeating: 0, count: 32)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
      throw GPUSearchError.randomFailed
    }
    return bytes
  }

  private typealias Dispatch = (MTLComputePipelineState, [MTLBuffer], Int)

  /// Encodes dispatches into one command buffer, each in its own encoder so
  /// that later ones see the writes of earlier ones.
  private func encode(_ dispatches: [Dispatch]) throws -> MTLCommandBuffer {
    guard let commandBuffer = queue.makeCommandBuffer() else {
      throw GPUSearchError.commandFailed("can't create a command buffer")
    }
    for (pipeline, buffers, threads) in dispatches {
      guard let encoder = commandBuffer.makeComputeCommandEncoder() else {
        throw GPUSearchError.commandFailed("can't create a compute encoder")
      }
      encoder.setComputePipelineState(pipeline)
      for (index, buffer) in buffers.enumerated() {
        encoder.setBuffer(buffer, offset: 0, index: index)
      }
      let width = min(pipeline.maxTotalThreadsPerThreadgroup, threads)
      encoder.dispatchThreads(
        MTLSize(width: threads, height: 1, depth: 1),
        threadsPerThreadgroup: MTLSize(width: width, height: 1, depth: 1))
      encoder.endEncoding()
    }
    return commandBuffer
  }

  private func run(_ dispatches: [Dispatch]) throws {
    let commandBuffer = try encode(dispatches)
    commandBuffer.commit()
    commandBuffer.waitUntilCompleted()
    if let error = commandBuffer.error { throw GPUSearchError.commandFailed("\(error)") }
  }
}
