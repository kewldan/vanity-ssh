import Foundation
import Testing

@testable import VanitySSH

@Suite struct Ed25519KeyTests {
  /// RFC 8032, section 7.1, test 1.
  @Test func derivesPublicKeyLikeRFC8032() throws {
    let key = try Ed25519Key(
      seed: hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"))
    #expect(
      key.publicKey == hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"))
  }

  @Test func writesKeysThatSSHKeygenReads() throws {
    let key = try Ed25519Key(seed: (0..<32).map { _ in UInt8.random(in: 0...255) })
    let directory = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("key").path
    try key.write(toPath: path, comment: "test@vanity")

    // ssh-keygen derives the public key from the private key file on its own.
    let derived = try sshKeygen(["-y", "-f", path])
    let publicLine = try String(contentsOfFile: path + ".pub", encoding: .utf8)
    #expect(derived.split(separator: " ").prefix(2) == publicLine.split(separator: " ").prefix(2))

    let listed = try sshKeygen(["-l", "-f", path + ".pub"])
    #expect(listed.contains("SHA256:\(key.fingerprint) test@vanity"))

    let mode = try FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? Int
    #expect(mode == 0o600)
  }

  @Test func refusesToOverwrite() throws {
    let key = try Ed25519Key(seed: [UInt8](repeating: 7, count: 32))
    let directory = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: directory) }
    let path = directory.appendingPathComponent("key").path
    FileManager.default.createFile(atPath: path + ".pub", contents: Data("keep".utf8))
    #expect(throws: KeyFileError.alreadyExists(path + ".pub")) {
      try key.write(toPath: path, comment: "")
    }
    #expect(!FileManager.default.fileExists(atPath: path))
  }
}

func hex(_ string: String) -> [UInt8] {
  var bytes: [UInt8] = []
  var index = string.startIndex
  while index < string.endIndex {
    let next = string.index(index, offsetBy: 2)
    bytes.append(UInt8(string[index..<next], radix: 16)!)
    index = next
  }
  return bytes
}

func temporaryDirectory() throws -> URL {
  let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
  return url
}

func sshKeygen(_ arguments: [String]) throws -> String {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
  process.arguments = arguments
  let pipe = Pipe()
  process.standardOutput = pipe
  try process.run()
  let output = pipe.fileHandleForReading.readDataToEndOfFile()
  process.waitUntilExit()
  #expect(process.terminationStatus == 0)
  return String(decoding: output, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
}
