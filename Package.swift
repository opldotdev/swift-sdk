// swift-tools-version: 6.1

import PackageDescription

let modernPublicModules = [
    "BSVCore",
    "BSVCrypto",
    "BSVKeys",
    "BSVMessage",
    "BSVScript",
    "BSVKVStore",
    "BSVStorage",
    "BSVTransaction",
    "BSVInterpreter",
    "BSVSPV",
    "BSVNetwork",
    "BSVOverlay",
    "BSVRegistry",
    "BSVWallet",
    "BSVAuth",
    "BSVIdentity",
]

let modernPublicModuleDependencies = modernPublicModules.map {
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
        .library(name: "BSVCompat", targets: ["BSVCompat"]),
    ] + modernPublicModules.map { module in
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
            dependencies: modernPublicModuleDependencies
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
                "BSVBigNum",
                "BSVCrypto",
                .product(name: "P256K", package: "swift-secp256k1"),
            ]
        ),
        .target(
            name: "BSVMessage",
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys"]
        ),
        .target(
            name: "BSVCompat",
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys"]
        ),
        .target(
            name: "BSVScript",
            dependencies: ["BSVCore", "BSVBigNum", "BSVCrypto", "BSVKeys"]
        ),
        .target(
            name: "BSVKVStore",
            dependencies: ["BSVKeys", "BSVScript"]
        ),
        .target(
            name: "BSVStorage",
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys"]
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
                "BSVKeys",
                "BSVScript",
                "BSVTransaction",
            ]
        ),
        .target(
            name: "BSVSPV",
            dependencies: ["BSVCore", "BSVCrypto", "BSVTransaction", "BSVInterpreter"]
        ),
        .target(
            name: "BSVNetwork",
            dependencies: ["BSVCore", "BSVTransaction", "BSVSPV"]
        ),
        .target(
            name: "BSVOverlay",
            dependencies: ["BSVCore", "BSVCrypto", "BSVKeys", "BSVScript", "BSVTransaction"]
        ),
        .target(
            name: "BSVRegistry",
            dependencies: ["BSVCore", "BSVKeys", "BSVOverlay", "BSVScript", "BSVTransaction", "BSVWallet"]
        ),
        .target(
            name: "BSVWallet",
            dependencies: [
                "BSVCore",
                "BSVCrypto",
                "BSVKeys",
                "BSVScript",
                "BSVTransaction",
            ]
        ),
        .target(
            name: "BSVAuth",
            dependencies: [
                "BSVCore",
                "BSVCrypto",
                "BSVKeys",
                "BSVTransaction",
                "BSVWallet",
            ]
        ),
        .target(
            name: "BSVIdentity",
            dependencies: ["BSVCore", "BSVKeys", "BSVScript", "BSVTransaction", "BSVWallet"]
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
            name: "BSVMessageTests",
            dependencies: ["BSVMessage", "BSVKeys", "BSVCrypto", "BSVCore"]
        ),
        .testTarget(
            name: "BSVCompatTests",
            dependencies: ["BSVCompat", "BSVKeys", "BSVCrypto", "BSVCore"]
        ),
        .testTarget(
            name: "BSVScriptTests",
            dependencies: ["BSVScript", "BSVCore", "BSVKeys"],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVKVStoreTests",
            dependencies: ["BSVKVStore", "BSVKeys", "BSVScript"]
        ),
        .testTarget(
            name: "BSVStorageTests",
            dependencies: ["BSVStorage", "BSVCore", "BSVCrypto", "BSVKeys"]
        ),
        .testTarget(
            name: "BSVTransactionTests",
            dependencies: ["BSVTransaction", "BSVCore", "BSVCrypto", "BSVScript"],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVSPVTests",
            dependencies: ["BSVSPV", "BSVTransaction", "BSVCore", "BSVCrypto", "BSVScript"],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVInterpreterTests",
            dependencies: [
                "BSVInterpreter", "BSVCore", "BSVCrypto", "BSVKeys",
                "BSVScript", "BSVTransaction", "BSVWallet",
            ],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVNetworkTests",
            dependencies: ["BSVNetwork", "BSVTransaction", "BSVSPV", "BSVCore"],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVOverlayTests",
            dependencies: ["BSVOverlay", "BSVCrypto", "BSVKeys", "BSVScript", "BSVCore", "BSVTransaction"]
        ),
        .testTarget(
            name: "BSVRegistryTests",
            dependencies: [
                "BSVRegistry", "BSVCore", "BSVKeys", "BSVOverlay", "BSVScript", "BSVTransaction",
                "BSVWallet",
            ]
        ),
        .testTarget(
            name: "BSVWalletTests",
            dependencies: ["BSVWallet", "BSVKeys", "BSVCrypto", "BSVCore", "BSVScript"],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVAuthTests",
            dependencies: [
                "BSVAuth", "BSVWallet", "BSVTransaction", "BSVKeys", "BSVCrypto", "BSVCore",
            ],
            exclude: ["README.md"]
        ),
        .testTarget(
            name: "BSVIdentityTests",
            dependencies: [
                "BSVIdentity", "BSVWallet", "BSVTransaction", "BSVScript", "BSVKeys", "BSVCore",
            ]
        ),
        .testTarget(
            name: "BSVConformanceTests",
            dependencies: [
                Target.Dependency.target(name: "BSV"),
                Target.Dependency.target(name: "BSVCompat"),
                .product(name: "Crypto", package: "swift-crypto"),
            ] + modernPublicModuleDependencies,
            resources: [.copy("Fixtures")]
        ),
    ],
    swiftLanguageModes: [.v6]
)
