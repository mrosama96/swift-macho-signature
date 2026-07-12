// swift-tools-version: 5.9
//
//  Package.swift
//  MachOSignature
//
//  Created by Osama Almanasra on 08/07/2026.
//
//  https://www.linkedin.com/in/osamamanasra
//
import PackageDescription

let package = Package(
    name: "MachOSignature",
    platforms: [.iOS(.v13), .macOS(.v11), .tvOS(.v13), .watchOS(.v6)],
    products: [
        .library(name: "MachOSignature", targets: ["MachOSignature"]),
    ],
    targets: [
        .target(name: "MachOSignature"),
        .testTarget(
            name: "MachOSignatureTests",
            dependencies: ["MachOSignature"]
        ),
    ]
)
