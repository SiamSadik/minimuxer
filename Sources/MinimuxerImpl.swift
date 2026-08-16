//
//  Minimuxer.swift
//  Minimuxer
//
//  Created by Magesh K on 4/7/26.
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation

private enum MinimuxerStatus{
    case started, inprogress, stopped
}

final internal class MinimuxerImpl: MinimuxerAPI {
    private actor State {
        var status: MinimuxerStatus = .stopped
        var mountTask: Task<Bool, Error>? = nil
        var lastDocsPath: String? = nil
        
        func with<T>(_ body: (isolated State) throws -> T) rethrows -> T {
            try body(self)
        }
    }
    private let state = State()
    
    var isrppairing: Bool { IdeviceGateway.shared.isRPPairing }
    
    var isLoggingEnabled = true
    
    var isPairingFileLoaded: Bool {
        return getPairingFileType() != .unknown
    }
    
    func getPairingFileType() -> PairingProtocol {
        return IdeviceGateway.shared.getPairingFileType()
    }


    func describeError(_ error: MinimuxerError) -> String {
        return error.description
    }
    
    func bindTunnelConfig(_ binding: TunnelConfigBinding) async {
        await NetworkIfaceScanner.shared.bindTunnelConfig(binding)
    }
    
    var isReady: Result<Bool, MinimuxerError> {
        get async {
            // check connection status first
            if !(Minimuxer.network.isWifiSatisfied  ||
                 Minimuxer.network.isWiredSatisfied ||
                 Minimuxer.network.isUsbSatisfied   ||
                 Minimuxer.network.isBridgeSatisfied
            ){
                debugLog("[minimuxer] minimuxer not ready: no network connection")
                return .failure(.noConnection("No wifi, wired, usb, or bridge interface satisfied"))
            }

            // check VPN Availability for all modes
            let net = Minimuxer.network
            let uTunPresent = net.isUTunAvailable
            if !uTunPresent {
                debugLog("[minimuxer] minimuxer not ready: no utun interface found")
                return .failure(.noVPN("No utun interface detected — LocalDevVPN is not connected"))
            }

            // check if pairing file is loaded
            let pairingType = getPairingFileType()
            if pairingType == .unknown {
                debugLog("[minimuxer] minimuxer not ready: no valid pairing file loaded")
                return .failure(.pairingFile(protocol: .lockdown, reason: "No valid pairing file has been loaded in Minimuxer"))
            }

            // check iKEv2 too if in lockdown mode and ios >= 26.4
            if !isrppairing && !net.isIKEv2IPSecAvailable {
                if #available(iOS 26.4, *) {
                    if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 27 {
                        // iOS 27 works with classic lockdown over a plain utun (0.6.3-era
                        // behavior) and with the source-bind relay (127.0.0.1 -> utun peer
                        // with the device's own WiFi IP as the socket source, so the
                        // source-IP check sees an in-subnet address) — the ipsec gate is
                        // a warning only on 27+.
                        debugLog("[minimuxer] iOS 27+ lockdown: no ipsec interface present, attempting lockdown via source-bind relay anyway")
                    } else {
                        debugLog("[minimuxer] minimuxer not ready: no ipsec interface (required for lockdown on iOS 26.4)")
                        return .failure(.invalidVPN("utun is present but no ipsec/IKEv2 interface found — LocalDevVPN may not support the lockdown protocol on iOS 26.4"))
                    }
                }
            }

            // then check if device is ready
            let tunnelPeerIp: String
            do {
                tunnelPeerIp = try await TunnelPeer.shared.ip()
            } catch {
                debugLog("[minimuxer] minimuxer not ready: tunnel peer IP not available despite tunnel iface being present")
                return .failure(.invalidVPN("VPN tunnel iface is up but tunnel peer IP is not yet available — VPN may not be routing device traffic correctly. Cause: \(error.localizedDescription)"))
            }
            
            let peerReachable = testDeviceConnection(ifaddr: tunnelPeerIp)
            if !peerReachable {
                debugLog("[minimuxer] minimuxer not ready: failed to connect to tunnel peer IP")
                return .failure(.invalidVPN("VPN tunnel iface is up and tunnel peer IP \(tunnelPeerIp) is known, but TCP port poll failed — device may be unreachable on this interface"))
            }


            let activeProtocol: PairingProtocol = isrppairing ? .rppairing : .lockdown

            let ddiMounted: Bool
            do {
                ddiMounted = try await runIdeviceCheckingVPN("while checking DDI mount status", fallback: false) {
                    try await isDDIMounted()
                }
            } catch let err as MinimuxerError {
                return .failure(err)
            }

            if isrppairing {
                guard ddiMounted else {
                    let msg = "dmg=\(ddiMounted) started=\(MuxerService.isListening)"
                    verboseLog("minimuxer not ready (RSD): \(msg)")
                    return .failure(.mount(protocol: activeProtocol, reason: msg))
                }
                return .success(true)
            }

            let deviceUDID: String?
            do {
                deviceUDID = try await runIdeviceCheckingVPN("while fetching device UDID", fallback: nil) {
                    try await fetchUDID()
                }
            } catch let err as MinimuxerError {
                return .failure(err)
            }

            verboseLog(
                "minimuxer status (usbmuxd): " +
                "deviceUDID=\(deviceUDID ?? "nil") " +
                "dmg=\(ddiMounted) " +
                "started=\(MuxerService.isListening) "
            )
            guard deviceUDID != nil else {
                return .failure(.invalidPairing(protocol: activeProtocol, reason: "Lockdown UDID not found"))
            }
            guard ddiMounted else {
                return .failure(.mount(protocol: activeProtocol, reason: "DeveloperDiskImage is not mounted"))
            }
            guard MuxerService.isListening else {
                return .failure(.muxerNotListening("Usbmuxd fake server is not listening"))
            }
            return .success(true)
        }
    } 

    @inline(__always)
    private func runIdeviceCheckingVPN<T>(_ context: String, fallback: T, action: () async throws -> T) async throws(MinimuxerError) -> T {
        do {
            return try await action()
        } catch let err as IdeviceGatewayError {
            if case .connectionFailed(let reason) = err,
               reason.lowercased().contains("broken pipe") || reason.lowercased().contains("brokenpipe") {
                throw MinimuxerError.noVPN("VPN tunnel connection severed \(context). Cause: \(reason)")
            }
            return fallback
        } catch {
            return fallback
        }
    }
    
    // This is required since we want to dissociate the caller priority from what rust internally uses so that
    // thread checker doesn't complain inversion of priority (ex: if caller was Task instantiated from MainThread,
    // then it is of .userInitiated priority by default, but our rust tokio threads are at .background priority
    //
    // NOTE: For now this wrapping is only required for IdeviceGateway apis that do device services like fetchUDID, install etc
    //
    @inline(__always)
    private func matchingPriority<T: Sendable>(priority: TaskPriority = .medium, _ body: @escaping @Sendable () async throws -> T) async throws -> T {
        try await Task.detached(priority: priority) {
            try await body()
        }.value
    }

    private func restartMuxerServer() async throws {
        guard !isrppairing else { return }
        // restartMuxerServer only applies to the lockdown protocol path
        guard let pairingDict = IdeviceGateway.shared.pairingDataDict else {
            debugLog("[minimuxer] ERROR: Pairing DICT missing...ignoring restart MuxerServer")
            throw MinimuxerError.pairingFile(protocol: .lockdown, reason: "Pairing dictionary is missing in gateway")
        }
        verboseLog("[minimuxer] loaded pairing file keys: \(pairingDict.keys)")

        guard let deviceUDID = pairingDict["UDID"] as? String else {
            debugLog("[minimuxer] ERROR: Pairing file missing UDID")
            throw MinimuxerError.pairingFile(protocol: .lockdown, reason: "Pairing file is missing UDID value")
        }

        // restart muxer
        MuxerService.stop()
        try await MuxerService.start(udid: deviceUDID)
    }
    
    
    func setLogging(_ enabled: Bool) {
        self.isLoggingEnabled = enabled
        IdeviceGateway.shared.setLogging(enabled)
    }
    
    func retargetUsbmuxdAddr() {
        verboseLog("[minimuxer] unsetenv(USBMUXD_SOCKET_ADDRESS)")
        unsetenv(MinimuxerConstants.usbmuxdEnvKey)
        verboseLog("[minimuxer] setenv(USBMUXD_SOCKET_ADDRESS, \(MinimuxerConstants.usbmuxdSocket))")
        setenv(MinimuxerConstants.usbmuxdEnvKey, MinimuxerConstants.usbmuxdSocket, 1)
        let value = String(cString: getenv(MinimuxerConstants.usbmuxdEnvKey))
        verboseLog("[minimuxer] getenv(USBMUXD_SOCKET_ADDRESS) = \(value)")
    }
    
    
    func start(pairingFile: String, mountPath: String) async throws {
        await Minimuxer.network.start()
        
        // actor serialization scope
        try await state.with{
            $0.status = .inprogress     // mark inprogress
            $0.lastDocsPath = mountPath // record the mountPath
        }
        // let idevice initialize its state and set isRPPairing
        try IdeviceGateway.shared.start(pairingFileContent: pairingFile)
        // retarget usbmuxd to our fake usbmuxd server (over network)
        retargetUsbmuxdAddr()
        // start our fake usbmuxd server for lockdown protocol based clients if required
        try await restartMuxerServer()

        // Diagnostic probe suite (test build): runs concurrently with the
        // initial mount attempt and prints to the console log. Includes the
        // TCP probe matrix with real errno, the Local Network permission
        // check, and the loopback lockdown + full-mount test.
        Task {
            await DiagnosticsProbe.shared.runSuite()
            await self.diagLoopbackMountAttempt()
        }

        do {
            try await matchingPriority{
                try await Mounter.shared.mount(docsPath: mountPath)
            }
        } catch {
            debugLog("[minimuxer] WARN: Initial DDI mount skipped during startup: \(error.localizedDescription)")
        }
        // mark ready!
        try await state.with{
            $0.status = .started
        }
    }

    func stop() async {
        // actor serialization scope
        try await state.with{
            $0.status = .inprogress // mark inprogress
            $0.mountTask?.cancel()  // cancel the task
        }
        try await state.with{
            $0.status = .inprogress
            $0.mountTask = nil
        }
        MuxerService.stop()
        // mark ready!
        try await state.with{
            $0.status = .stopped
        }
    }
    
    func restart() async throws {
        verboseLog("[minimuxer] Restarting services...")
        let activeProtocol: PairingProtocol = isrppairing ? .rppairing : .lockdown
        guard let pairingData = IdeviceGateway.shared.pairingFileData,
              let pairingFile = String(data: pairingData, encoding: .utf8) else {
            debugLog("[minimuxer] restart: no existing pairing file — cannot restart")
            throw MinimuxerError.pairingFile(protocol: activeProtocol, reason: "No existing pairing file found in gateway during restart")
        }
        guard let mountPath = await state.lastDocsPath else {
            throw MinimuxerError.mount(protocol: activeProtocol, reason: "lastDocsPath is nil during restart")
        }
        await stop()
        try await start(pairingFile: pairingFile, mountPath: mountPath)
        await Minimuxer.network.refreshEndpoint()
    }
    
    func mountDDI(docsPath: String) async throws -> Bool {
        // actor serialization scope
        await state.with{
            $0.lastDocsPath = docsPath  // record the mountPath
            $0.mountTask?.cancel()      // cancel the task
        }
        let task = Task.detached(priority: .medium) {
            try await Mounter.shared.mount(docsPath: docsPath)
        }
        await state.with{
            $0.mountTask = task
        }
        return try await task.value
    }
    func isDDIMounted() async throws -> Bool {
        try await matchingPriority{
            try IdeviceGateway.shared.isDDIMounted()
        }
    }

    /// Diagnostic (test build): switch the shared tunnel peer to 127.0.0.1 and
    /// attempt the FULL DDI mount over loopback lockdown — the decisive test of
    /// whether the app can reach lockdownd at all (and mount the DDI) when the
    /// Local Network path is denied. Restores the original peer afterwards.
    func diagLoopbackMountAttempt() async {
        verboseLog("[minimuxer] [diag] === LOOPBACK FULL-MOUNT TEST (peer -> 127.0.0.1) ===")
        let probe = DiagnosticsProbe.shared.probeTCP("127.0.0.1", port: MinimuxerConstants.lockdowndPort, timeoutMs: 2000)
        guard probe.isConnected else {
            verboseLog("[minimuxer] [diag] loopback 62078 not connected (\(probe)) — skipping full-mount test")
            return
        }
        guard let docsPath = await state.lastDocsPath else {
            verboseLog("[minimuxer] [diag] lastDocsPath is nil — skipping full-mount test")
            return
        }
        let original = try? await TunnelPeer.shared.ip()
        verboseLog("[minimuxer] [diag] switching peer \(original ?? "nil") -> 127.0.0.1")
        await TunnelPeer.shared.update("127.0.0.1")
        IdeviceGateway.shared.setDiagnosticFFILogging(true)
        do {
            let mounted = try await Mounter.shared.mount(docsPath: docsPath, maxRetries: 1)
            verboseLog("[minimuxer] [diag] LOOPBACK FULL-MOUNT: SUCCESS (mounted=\(mounted)) — DDI path works via 127.0.0.1!")
        } catch {
            verboseLog("[minimuxer] [diag] LOOPBACK FULL-MOUNT: FAILED — \(error)")
        }
        IdeviceGateway.shared.setDiagnosticFFILogging(false)
        if let original {
            await TunnelPeer.shared.update(original)
            verboseLog("[minimuxer] [diag] peer restored -> \(original)")
        }
    }

    func runDiagnostics() async {
        verboseLog("[minimuxer] [diag] === manual diagnostics run requested ===")
        await DiagnosticsProbe.shared.runSuite()
        await diagLoopbackMountAttempt()
        verboseLog("[minimuxer] [diag] === manual diagnostics run complete ===")
    }

    func reinitializePairingData(pairingFile: String) async throws {
        verboseLog("[minimuxer] Reinitializing with new pairing file...")
        await stop()
        guard let mountPath = await state.lastDocsPath else {
            let activeProtocol: PairingProtocol = isrppairing ? .rppairing : .lockdown
            throw MinimuxerError.mount(protocol: activeProtocol, reason: "start() should be invoked before requesting pairing data reinitialization. cause: lastDocsPath is nil")
        }
        try await start(pairingFile: pairingFile, mountPath: mountPath)
    }

    func fetchUDID() async throws -> String? {
        try await matchingPriority{
            try IdeviceGateway.shared.fetchUDID()
        }
    }
    
    private func testTCPPort(ip: String, port: UInt16) -> Bool {
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        inet_pton(AF_INET, ip, &addr.sin_addr)

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        _ = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let result = poll(&pfd, 1, 100)
        return result > 0 && (pfd.revents & Int16(POLLOUT)) != 0
    }

    func testDeviceConnection(ifaddr: String?) -> Bool {
        guard let ip = ifaddr else { return false }
        if testTCPPort(ip: ip, port: MinimuxerConstants.rsdPort) {
            return true
        }
        return testTCPPort(ip: ip, port: MinimuxerConstants.lockdowndPort)
    }


    func yeetAppAfc(bundleId: String, ipaBytes: Data) async throws {
        try await matchingPriority{
            try IdeviceGateway.shared.yeetAppAfc(bundleId: bundleId, ipaBytes: ipaBytes)
        }
    }

    func installIpa(bundleId: String) async throws {
        try await matchingPriority{
            try IdeviceGateway.shared.installIpa(bundleId: bundleId)
        }
    }

    func removeApp(bundleId: String) async throws {
        try await matchingPriority{
            try IdeviceGateway.shared.removeApp(bundleId: bundleId)
        }
    }

    private func ensureDDIMounted() async throws {
        let isMounted = (try? await IdeviceGateway.shared.isDDIMounted()) ?? false
        if isMounted {
            return
        }
        guard let mountPath = await state.lastDocsPath else {
            let activeProtocol: PairingProtocol = isrppairing ? .rppairing : .lockdown
            throw MinimuxerError.mount(protocol: activeProtocol, reason: "DDI mount path not set")
        }
        verboseLog("[minimuxer] DDI not mounted, mounting now before launching debug session...")
        _ = try await Mounter.shared.mount(docsPath: mountPath)
    }

    func debugApp(appId: String) async throws {
        try await ensureDDIMounted()
        try await matchingPriority{
            try IdeviceGateway.shared.debugApp(appId: appId)
        }
    }

    func attachDebugger(pid: UInt32) async throws {
        try await ensureDDIMounted()
        try await matchingPriority{
            try IdeviceGateway.shared.debugProcess(pid: pid)
        }
    }

    func installProvisioningProfile(profile: Data) async throws {
        try await matchingPriority{
            try IdeviceGateway.shared.installProvisioningProfile(profile: profile)
        }
    }

    func removeProvisioningProfile(id: String) async throws {
        try await matchingPriority{
            try IdeviceGateway.shared.removeProvisioningProfile(id: id)
        }
    }

    func dumpProfiles(docsPath: String) async throws -> String {
        try await matchingPriority{
            try IdeviceGateway.shared.dumpProfiles(docsPath: docsPath)
        }
    }

    func afcListDirectory(bundleId: String, path: String) async throws -> [String] {
        try await matchingPriority {
            try IdeviceGateway.shared.afcListDirectory(bundleId: bundleId, path: path)
        }
    }

    func afcReadFile(bundleId: String, path: String) async throws -> Data {
        try await matchingPriority {
            try IdeviceGateway.shared.afcReadFile(bundleId: bundleId, path: path)
        }
    }

    func afcGetFileInfo(bundleId: String, path: String) async throws -> (isDirectory: Bool, fileSize: Int64) {
        try await matchingPriority {
            try IdeviceGateway.shared.afcGetFileInfo(bundleId: bundleId, path: path)
        }
    }
}

private func getTag(level: String) -> String {
    let formatter = DateFormatter()
    formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    formatter.locale = Locale(identifier: "en_US_POSIX")
    let timestamp = formatter.string(from: Date())
    return "\(timestamp) \(level): "
}

@inline(__always)
func debugLog(_ text: @autoclosure () -> String) {
    let message = text()
    if !message.isEmpty && message.allSatisfy({ $0 == "\n" || $0 == "\r" }) {
        print(message, terminator: "")
    } else {
        print("\(getTag(level: "[D]"))\(message)")
    }
}


@inline(__always)
func verboseLog(_ text: @autoclosure () -> String) {
    if Minimuxer.shared.isLoggingEnabled {
        let message = text()
        if !message.isEmpty && message.allSatisfy({ $0 == "\n" || $0 == "\r" }) {
            print(message, terminator: "")
        } else {
            print("\(getTag(level: "[V]"))\(message)")
        }
    }
}
