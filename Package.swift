// swift-tools-version: 6.1

import PackageDescription

let publicModules = [
    "BSVCore",
    "BSVCrypto",
    "BSVKeys",
    "BSVScript",
    "BSVTransaction",
    "BSVInterpreter",
    "BSVSPV",
    "BSVNetwork",
    "BSVWallet",
    "BSVAuth",
    "BSVServices",
]

let publicModuleDependencies = publicModules.map {
    Target.Dependency.target(name: $0)
}

let package = Package(
    name: "swift-sdk",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
        .visionOS(.v1),
    ],
    products: [
        .library(name: "BSV", targets: ["BSV"]),
    ] + publicModules.map { module in
        .library(name: module, targets: [module])
    },
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-crypto.git",
            exact: "4.5.1"
        ),
        .package(
            url: "https://github.com/21-DOT-DEV/swift-secp256k1.git",
            exact: "0.23.2"
        ),
        .package(
            url: "https://github.com/attaswift/BigInt.git",
            exact: "5.7.0"
        ),
    ],
    targets: [
        .target(
            name: "BSV",
            dependencies: publicModuleDependencies
        ),
        .target(name: "BSVCore"),
        .target(
            name: "BSVBigNum",
            dependencies: [
                "BSVCore",
                .product(name: "BigInt", package: "BigInt"),
            ]
        ),
        .target(
            name: "BSVCrypto",
            dependencies: [
                "BSVCore",
                "BSVBigNum",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "CryptoExtras", package: "swift-crypto"),
            ]
        ),
        .target(
            name: "BSVKeys",
            dependencies: [
                "BSVCore",
                "BSVCrypto",
                .product(name: "P256K", package: "swift-secp256k1"),
            ]
        ),
        .target(
            name: "BSVScript",
            dependencies: ["BSVCore", "BSVBigNum", "BSVCrypto", "BSVKeys"]
        ),
        .target(
            name: "BSVTransaction",
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys", "BSVScript"]
        ),
        .target(
            name: "BSVInterpreter",
            dependencies: [
                "BSVCore",
                "BSVBigNum",
                "BSVCrypto",
                "BSVScript",
                "BSVTransaction",
            ]
        ),
        .target(
            name: "BSVSPV",
            dependencies: ["BSVCore", "BSVTransaction", "BSVInterpreter"]
        ),
        .target(
            name: "BSVNetwork",
            dependencies: ["BSVCore", "BSVTransaction", "BSVSPV"]
        ),
        .target(
            name: "BSVWallet",
            dependencies: [
                "BSVCore",
                "BSVCrypto",
                "BSVKeys",
                "BSVScript",
                "BSVTransaction",
                "BSVNetwork",
            ]
        ),
        .target(
            name: "BSVAuth",
            dependencies: [
                "BSVCore",
                "BSVCrypto",
                "BSVKeys",
                "BSVScript",
                "BSVTransaction",
                "BSVNetwork",
                "BSVWallet",
            ]
        ),
        .target(
            name: "BSVServices",
            dependencies: [
                "BSVCore",
                "BSVCrypto",
                "BSVKeys",
                "BSVScript",
                "BSVTransaction",
                "BSVNetwork",
                "BSVWallet",
                "BSVAuth",
            ]
        ),
        .testTarget(
            name: "BSVCoreTests",
            dependencies: ["BSVCore"],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVCryptoTests",
            dependencies: ["BSVCrypto", "BSVCore"],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVBigNumTests",
            dependencies: ["BSVBigNum"],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVKeysTests",
            dependencies: ["BSVKeys", "BSVCrypto", "BSVCore"],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVScriptTests",
            dependencies: ["BSVScript"],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVConformanceTests",
            dependencies: [
                Target.Dependency.target(name: "BSV"),
                .product(name: "Crypto", package: "swift-crypto"),
            ] + publicModuleDependencies,
            resources: [.copy("Fixtures")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
