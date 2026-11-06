import Foundation

/// Errors from writing key files.
public enum KeyFileError: Error, Equatable, CustomStringConvertible {
  case alreadyExists(String)
  case writeFailed(String, Int32)

  public var description: String {
    switch self {
    case .alreadyExists(let path):
      return "\(path) already exists; refusing to overwrite it."
    case .writeFailed(let path, let code):
      return "Can't write \(path): \(String(cString: strerror(code)))."
    }
  }
}

extension Ed25519Key {
  /// The private key in the unencrypted `openssh-key-v1` format that
  /// `ssh-keygen -N ""` produces.
  public func privateKeyPEM(comment: String) -> String {
    let check = UInt32.random(in: .min ... .max)
    var secret = SSHWireWriter()
    secret.append(uint32: check)
    secret.append(uint32: check)
    secret.append(string: Array(Self.keyType.utf8))
    secret.append(string: publicKey)
    secret.append(string: seed + publicKey)
    secret.append(string: Array(comment.utf8))
    var padding: UInt8 = 1
    while secret.bytes.count % 8 != 0 {
      secret.append(raw: [padding])
      padding += 1
    }

    var file = SSHWireWriter()
    file.append(raw: Array("openssh-key-v1".utf8) + [0])
    file.append(string: Array("none".utf8))  // Cipher.
    file.append(string: Array("none".utf8))  // KDF.
    file.append(string: [])  // KDF options.
    file.append(uint32: 1)  // Number of keys.
    file.append(string: publicKeyBlob)
    file.append(string: secret.bytes)

    let body = Data(file.bytes).base64EncodedString()
    var lines = ["-----BEGIN OPENSSH PRIVATE KEY-----"]
    var index = body.startIndex
    while index < body.endIndex {
      let end = body.index(index, offsetBy: 70, limitedBy: body.endIndex) ?? body.endIndex
      lines.append(String(body[index..<end]))
      index = end
    }
    lines.append("-----END OPENSSH PRIVATE KEY-----")
    return lines.joined(separator: "\n") + "\n"
  }

  /// The `ssh-ed25519 AAAA... comment` line of a `.pub` file.
  public func authorizedKeyLine(comment: String) -> String {
    let line = "\(Self.keyType) \(Data(publicKeyBlob).base64EncodedString())"
    return comment.isEmpty ? line : "\(line) \(comment)"
  }

  /// Writes `path` (mode 0600) and `path.pub` (mode 0644). Never overwrites.
  public func write(toPath path: String, comment: String) throws {
    let publicPath = path + ".pub"
    for candidate in [path, publicPath] where FileManager.default.fileExists(atPath: candidate) {
      throw KeyFileError.alreadyExists(candidate)
    }
    try Self.create(path, contents: privateKeyPEM(comment: comment), mode: 0o600)
    do {
      try Self.create(publicPath, contents: authorizedKeyLine(comment: comment) + "\n", mode: 0o644)
    } catch {
      unlink(path)
      throw error
    }
  }

  private static func create(_ path: String, contents: String, mode: mode_t) throws {
    let fd = open(path, O_WRONLY | O_CREAT | O_EXCL, mode)
    guard fd >= 0 else {
      throw errno == EEXIST ? KeyFileError.alreadyExists(path) : .writeFailed(path, errno)
    }
    defer { close(fd) }
    let bytes = Array(contents.utf8)
    let written = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
    guard written == bytes.count else { throw KeyFileError.writeFailed(path, errno) }
  }
}
