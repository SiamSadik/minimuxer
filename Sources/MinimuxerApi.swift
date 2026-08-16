//
//  MinimuxerApi.swift
//  Minimuxer
//
//  Created by Magesh K on 4/7/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation

public enum MinimuxerComponent: String {
    case heartbeat
    case mounter
}

public struct TunnelConfigBinding: Sendable {
    public let setTunnelIfaceIp: @Sendable (String?) -> Void
    public let setTunnelPeerIp: @Sendable (String?) -> Void
    public let setSubnetMask: @Sendable (String?) -> Void

    public init(
        setTunnelIfaceIp: @escaping @Sendable (String?) -> Void,
        setTunnelPeerIp: @escaping @Sendable (String?) -> Void,
        setSubnetMask: @escaping @Sendable (String?) -> Void
    ) {
        self.setTunnelIfaceIp = setTunnelIfaceIp
        self.setTunnelPeerIp = setTunnelPeerIp
        self.setSubnetMask = setSubnetMask
    }
}

public protocol MinimuxerAPI: AnyObject {
    var isrppairing: Bool { get }
    var isLoggingEnabled: Bool { get }
    var isPairingFileLoaded: Bool { get }
    func getPairingFileType() -> PairingProtocol
    
    var isReady: Result<Bool, MinimuxerError> { get async }
    func describeError(_ error: MinimuxerError) -> String
    func bindTunnelConfig(_ binding: TunnelConfigBinding) async
    func setLogging(_ enabled: Bool)

    func start(pairingFile: String, mountPath: String) async throws
    func stop() async throws
    func restart() async throws
    func reinitializePairingData(pairingFile: String) async throws
    func mountDDI(docsPath: String) async throws -> Bool
    func isDDIMounted() async throws -> Bool

    /// Diagnostic probe suite (test build): TCP probe matrix with real errno,
    /// Local Network permission check, loopback lockdown test, and a full DDI
    /// mount attempt via 127.0.0.1. Output goes to the console log.
    func runDiagnostics() async

    func fetchUDID() async throws -> String?
    func testDeviceConnection(ifaddr: String?) -> Bool

    func yeetAppAfc(bundleId: String, ipaBytes: Data) async throws
    func installIpa(bundleId: String) async throws
    func removeApp(bundleId: String) async throws
    func debugApp(appId: String) async throws
    func attachDebugger(pid: UInt32) async throws
    func installProvisioningProfile(profile: Data) async throws
    func removeProvisioningProfile(id: String) async throws
    func dumpProfiles(docsPath: String) async throws -> String

    func afcListDirectory(bundleId: String, path: String) async throws -> [String]
    func afcReadFile(bundleId: String, path: String) async throws -> Data
    func afcGetFileInfo(bundleId: String, path: String) async throws -> (isDirectory: Bool, fileSize: Int64)
}

public enum Minimuxer {
    public static let shared: any MinimuxerAPI = MinimuxerImpl()
    public static let network: any NetworkObserverAPI = NetworkObserverService()
    public static let wirelessPair: any WirelessPairAPI = WirelessPairService()
}

// MARK: - Network Observer API

public protocol NetworkObserverAPI: AnyObject {
    var isWifiSatisfied: Bool { get }
    var isWiredSatisfied: Bool { get }
    var isUsbSatisfied: Bool { get }
    var isBridgeSatisfied: Bool { get }
    var isUTunAvailable: Bool { get }
    var isIKEv2IPSecAvailable: Bool { get }

    @discardableResult
    func start() async -> Bool
    
    @discardableResult
    func stop() async -> Bool

    func refreshEndpoint() async
}

// MARK: - Wireless Pair API

public struct WirelessPairPairedDevice: Sendable {
    public let name: String
    public let model: String
    public let udid: String
    public let pairingFilePath: String
    
    public init(name: String, model: String, udid: String, pairingFilePath: String) {
        self.name = name
        self.model = model
        self.udid = udid
        self.pairingFilePath = pairingFilePath
    }
}

public protocol WirelessPairAPI: AnyObject {
    var onPinReceived: ((String) -> Void)? { get set }
    var onReadyToPair: ((String, Int) -> Void)? { get set }
    
    func start(
        hostName: String,
        hostModel: String,
        outPath: String,
        completion: @escaping (Result<WirelessPairPairedDevice, Swift.Error>) -> Void
    )
    
    func stop()
}

public extension WirelessPairAPI {
    func start(
        outPath: String,
        completion: @escaping (Result<WirelessPairPairedDevice, Swift.Error>) -> Void
    ){
        start(
            hostName: MinimuxerConstants.defaultHostName,
            hostModel: MinimuxerConstants.defaultHostModel,
            outPath: outPath,
            completion: completion
        )
    }
}
