import CryptoKit
import Foundation

/// An Ed25519 key pair in the form OpenSSH uses: a 32-byte seed and the
/// public key derived from it as RFC 8032 specifies.
public struct Ed25519Key: Sendable {
  public static let keyType = "ssh-ed25519"

  /// The secret. Anyone who has it can sign as this key.
  public let seed: [UInt8]
  public let publicKey: [UInt8]

  public init(seed: [UInt8]) throws {
    precondition(seed.count == 32, "An Ed25519 seed is 32 bytes")
    self.seed = seed
    let privateKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    publicKey = Array(privateKey.publicKey.rawRepresentation)
  }

  /// The public key as an SSH wire blob: string(key type) || string(key).
  public var publicKeyBlob: [UInt8] {
    var writer = SSHWireWriter()
    writer.append(string: Array(Self.keyType.utf8))
    writer.append(string: publicKey)
    return writer.bytes
  }

  /// The fingerprint `ssh-keygen -l` prints, without the `SHA256:` prefix.
  public var fingerprint: String {
    Data(SHA256.hash(data: publicKeyBlob)).base64EncodedString()
      .trimmingCharacters(in: CharacterSet(charactersIn: "="))
  }
}

/// Builds SSH wire-format byte strings (RFC 4251).
struct SSHWireWriter {
  private(set) var bytes: [UInt8] = []

  mutating func append(uint32 value: UInt32) {
    bytes += [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: value >> $0) }
  }

  mutating func append(string value: [UInt8]) {
    append(uint32: UInt32(value.count))
    bytes += value
  }

  mutating func append(raw value: [UInt8]) {
    bytes += value
  }
}
