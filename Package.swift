// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "vanity-ssh",
  platforms: [.macOS(.v13)],
  products: [
    .executable(name: "vanity-ssh", targets: ["vanity-ssh"]),
    .library(name: "VanitySSH", targets: ["VanitySSH"]),
  ],
  dependencies: [
    .package(url: "https://github.com/apple/swift-argument-parser", from: "1.5.0")
  ],
  targets: [
    .target(
      name: "VanitySSH",
      exclude: ["Metal"]
    ),
    .executableTarget(
      name: "vanity-ssh",
      dependencies: [
        "VanitySSH",
        .product(name: "ArgumentParser", package: "swift-argument-parser"),
      ]
    ),
    .testTarget(
      name: "VanitySSHTests",
      dependencies: ["VanitySSH"]
    ),
  ]
)
