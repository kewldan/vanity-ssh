import ArgumentParser
import Foundation
import VanitySSH

extension MatchPosition: ExpressibleByArgument {}

@main
struct VanitySSHCommand: ParsableCommand {
  static let configuration = CommandConfiguration(
    commandName: "vanity-ssh",
    abstract: "Find an Ed25519 SSH key with a custom SHA256 fingerprint, using the GPU.",
    discussion: """
      The pattern is matched against the base64 part of the fingerprint that \
      `ssh-keygen -l` prints, case-insensitively by default. Every extra letter \
      makes the search about 32 times longer (64 with --case-sensitive).

      Examples:
        vanity-ssh kewl
        vanity-ssh dano --position suffix -o ~/.ssh/id_ed25519_dano
        vanity-ssh --benchmark
      """,
    version: VanitySSH.version
  )

  @Argument(help: "Text to look for: A-Z, a-z, 0-9, + and /.")
  var pattern: String?

  @Option(name: .shortAndLong, help: "Where the pattern must appear.")
  var position: MatchPosition = .prefix

  @Flag(help: "Match letter case exactly.")
  var caseSensitive = false

  @Option(name: .shortAndLong, help: "Private key path. The public key goes to <path>.pub.")
  var output = "id_ed25519_vanity"

  @Option(name: [.customShort("C"), .long], help: "Key comment. Defaults to user@host.")
  var comment: String?

  @Flag(help: "Measure keys per second and exit.")
  var benchmark = false

  @Option(help: "Benchmark length in seconds.")
  var duration: Double = 10

  @Option(
    help: ArgumentHelp(
      "Table window in bits: 16 (125 MB, fastest) or 8 (1 MB).", visibility: .hidden))
  var window = 16

  @Option(help: ArgumentHelp("Keys per GPU thread.", visibility: .hidden))
  var keysPerThread = 32

  func validate() throws {
    if !benchmark && pattern == nil {
      throw ValidationError("Give a pattern to look for, or --benchmark.")
    }
    if let pattern {
      do {
        _ = try Pattern(pattern, position: position, caseSensitive: caseSensitive)
      } catch let error as PatternError {
        throw ValidationError(error.description)
      }
    }
  }

  func run() throws {
    var options = GPUSearchOptions()
    options.windowBits = window
    options.keysPerThread = keysPerThread

    if benchmark {
      let searcher = try makeSearcher(options)
      log("Benchmarking for \(Format.duration(duration))…")
      let result = try searcher.benchmark(seconds: duration)
      print("\(Format.count(result.keysPerSecond)) keys/s on \(searcher.device.name)")
      return
    }

    let pattern = try Pattern(self.pattern!, position: position, caseSensitive: caseSensitive)
    let path = (output as NSString).expandingTildeInPath
    for candidate in [path, path + ".pub"] where FileManager.default.fileExists(atPath: candidate) {
      throw ValidationError("\(candidate) already exists; choose another path with -o.")
    }

    let casing = caseSensitive ? "case-sensitive" : "any case"
    log(
      "Looking for \"\(pattern.text)\" (\(position.rawValue), \(casing)): "
        + "~\(Format.count(pattern.expectedAttempts)) keys on average.")
    let searcher = try makeSearcher(options)

    let progress = ProgressLine(expected: pattern.expectedAttempts)
    guard let key = try searcher.search(pattern: pattern, shouldContinue: progress.update) else {
      return
    }
    progress.finish()

    let keyComment = comment ?? Self.defaultComment()
    try key.write(toPath: path, comment: keyComment)
    print("SHA256:\(key.fingerprint)")
    log(
      """

      Private key: \(path)
      Public key:  \(path).pub

      The key has no passphrase. To add one: ssh-keygen -p -f \(path)
      """)
  }

  private func makeSearcher(_ options: GPUSearchOptions) throws -> GPUSearcher {
    log("Building a \(Format.bytes(options.tableBytes)) table on the GPU…")
    let searcher = try GPUSearcher(options: options)
    log("Using \(searcher.device.name).")
    return searcher
  }

  private static func defaultComment() -> String {
    var host = [CChar](repeating: 0, count: 256)
    gethostname(&host, host.count)
    let bytes = host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
    let name = String(decoding: bytes, as: UTF8.self).split(separator: ".").first ?? "localhost"
    return "\(NSUserName())@\(name)"
  }
}

/// Writes a message to standard error, keeping standard output for results.
func log(_ message: String) {
  FileHandle.standardError.write(Data((message + "\n").utf8))
}

/// A progress line on standard error: redrawn in place on a terminal, one line
/// per minute otherwise.
final class ProgressLine {
  private let expected: Double
  private let interactive = isatty(STDERR_FILENO) != 0
  private var lastDraw = Date.distantPast

  init(expected: Double) {
    self.expected = expected
  }

  func update(_ progress: SearchProgress) -> Bool {
    let now = Date()
    guard now.timeIntervalSince(lastDraw) >= (interactive ? 0.5 : 60) else { return true }
    lastDraw = now
    let rate = progress.keysPerSecond
    let eta = rate > 0 ? Format.duration(expected / rate) : "?"
    let line =
      "\(Format.duration(progress.elapsed)) · \(Format.count(Double(progress.attempts))) keys"
      + " · \(Format.count(rate))/s · mean time \(eta)"
    FileHandle.standardError.write(Data((interactive ? "\r\u{1B}[K\(line)" : line + "\n").utf8))
    return true
  }

  func finish() {
    if interactive { FileHandle.standardError.write(Data("\r\u{1B}[K".utf8)) }
  }
}

enum Format {
  static func count(_ value: Double) -> String {
    let units: [(Double, String)] = [(1e12, "T"), (1e9, "G"), (1e6, "M"), (1e3, "k")]
    for (scale, unit) in units where value >= scale {
      return String(format: "%.1f%@", value / scale, unit)
    }
    return String(format: "%.0f", value)
  }

  static func duration(_ seconds: Double) -> String {
    switch seconds {
    case ..<60: return String(format: "%.0fs", seconds)
    case ..<3600: return String(format: "%.0fm", seconds / 60)
    case ..<(86400 * 2): return String(format: "%.1fh", seconds / 3600)
    case ..<(86400 * 365): return String(format: "%.0f days", seconds / 86400)
    default: return String(format: "%.0f years", seconds / (86400 * 365))
    }
  }

  static func bytes(_ count: Int) -> String {
    count >= 1 << 20 ? "\(count >> 20) MB" : "\(count >> 10) KB"
  }
}
