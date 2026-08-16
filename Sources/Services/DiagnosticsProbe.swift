//
//  DiagnosticsProbe.swift
//  Minimuxer
//
//  Diagnostic probe suite for the tunnel-bypass TEST build.
//
//  Purpose: empirically verify WHY lockdown service connections fail on the
//  phone (iOS 27 beta 5) so we can stop guessing between:
//    (A) iOS 26.4+ lockdown kernel/policy protection (EPERM at connect from
//        any non-paired source, including the device's own IP), and
//    (B) the iOS Local Network privacy gate (blanket EPERM on ALL TCP to LAN
//        addresses when the permission was never granted to this app).
//
//  What it runs (all output goes to the console log via verboseLog):
//    1. TCP probe matrix with the REAL errno (non-blocking connect + poll +
//       getsockopt(SO_ERROR)) so EPERM (policy denial) is distinguishable
//       from ECONNREFUSED (no listener) and ETIMEDOUT (dropped).
//       Targets: own WiFi IP, loopback, utun peer/device, gateway, far end.
//    2. Kernel source-address discovery via the UDP-connect trick (which
//       interface the kernel routes a connection through: en0 vs utun).
//    3. A best-effort Local Network permission probe (temporary NWListener).
//    4. If loopback lockdown answers, an image-mounter service round-trip via
//       127.0.0.1 with the FFI logger bumped to level 4.
//    5. A printed verdict (LAN gate open/closed, lockdown-specific vs blanket
//       block, loopback lockdown availability).
//

import Foundation
import Darwin
import Network

final class DiagnosticsProbe {

    static let shared = DiagnosticsProbe()
    private init() {}

    // MARK: - Outcome

    enum Outcome: CustomStringConvertible {
        case connected(sourceIP: String?, latencyMs: Int64)
        case error(errnoValue: Int32, message: String)
        case timeout(ms: Int)
        case setup(String)

        var description: String {
            switch self {
            case .connected(let src, let ms):
                return "CONNECTED(source \(src ?? "?"), \(ms)ms)"
            case .error(let e, let m):
                return "ERRNO \(e) (\(m))"
            case .timeout(let ms):
                return "TIMEOUT(\(ms)ms)"
            case .setup(let s):
                return "SETUP-FAIL(\(s))"
            }
        }

        var isConnected: Bool {
            if case .connected = self { return true }
            return false
        }

        var errnoValue: Int32? {
            if case .error(let e, _) = self { return e }
            return nil
        }
    }

    // MARK: - TCP probe with the REAL errno

    /// Blocking-style TCP probe. Uses a non-blocking connect + poll + SO_ERROR
    /// so the REAL errno is surfaced (the existing `testTCPPort` can
    /// spuriously report success when the connect is policy-denied).
    func probeTCP(_ ip: String, port: UInt16, timeoutMs: Int = 2000, bindSource: String? = nil) -> Outcome {
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, ip, &addr.sin_addr) == 1 else {
            return .setup("inet_pton(\(ip)) failed")
        }

        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return .setup("socket() errno=\(errno)") }
        defer { close(fd) }

        if let src = bindSource {
            var saddr = sockaddr_in()
            saddr.sin_family = sa_family_t(AF_INET)
            saddr.sin_port = 0
            guard inet_pton(AF_INET, src, &saddr.sin_addr) == 1 else {
                return .setup("inet_pton(\(src)) failed")
            }
            let brc = withUnsafePointer(to: &saddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if brc != 0 {
                return .setup("bind(\(src)) errno=\(errno)")
            }
        }

        let flags = fcntl(fd, F_GETFL, 0)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)

        let startNs = DispatchTime.now().uptimeNanoseconds
        let crc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        let connectErrno = errno
        var elapsed = Int64((DispatchTime.now().uptimeNanoseconds - startNs) / 1_000_000)

        var outcome: Outcome
        if crc == 0 {
            outcome = .connected(sourceIP: nil, latencyMs: elapsed)
        } else if connectErrno == EINPROGRESS {
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let pr = poll(&pfd, 1, Int32(timeoutMs))
            elapsed = Int64((DispatchTime.now().uptimeNanoseconds - startNs) / 1_000_000)
            if pr == 0 {
                outcome = .timeout(ms: timeoutMs)
            } else {
                var soerr: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                _ = getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len)
                if soerr == 0 {
                    outcome = .connected(sourceIP: nil, latencyMs: elapsed)
                } else {
                    outcome = .error(errnoValue: soerr, message: String(cString: strerror(soerr)))
                }
            }
        } else {
            outcome = .error(errnoValue: connectErrno, message: String(cString: strerror(connectErrno)))
        }

        if case .connected = outcome {
            var name = sockaddr_storage()
            var namelen = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let rc = withUnsafeMutablePointer(to: &name) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(fd, $0, &namelen)
                }
            }
            if rc == 0 {
                var hostBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                let sa = withUnsafeMutablePointer(to: &name) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { $0 }
                }
                if getnameinfo(sa, namelen, &hostBuf, socklen_t(hostBuf.count), nil, 0, NI_NUMERICHOST) == 0 {
                    return .connected(sourceIP: String(cString: hostBuf), latencyMs: elapsed)
                }
            }
            return .connected(sourceIP: nil, latencyMs: elapsed)
        }
        return outcome
    }

    // MARK: - Kernel source-address discovery (UDP trick)

    /// connect() a UDP socket to `destination` (no packets are sent) and read
    /// back the source address the kernel picked. Tells us which interface the
    /// kernel routes a connection to that destination through (en0 vs utun).
    func kernelSourceIP(destination: String, port: UInt16 = 9) -> String? {
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, destination, &addr.sin_addr) == 1 else { return nil }
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else { return nil }
        var name = sockaddr_storage()
        var namelen = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let grc = withUnsafeMutablePointer(to: &name) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &namelen)
            }
        }
        guard grc == 0 else { return nil }
        var hostBuf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        let sa = withUnsafeMutablePointer(to: &name) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { $0 }
        }
        guard getnameinfo(sa, namelen, &hostBuf, socklen_t(hostBuf.count), nil, 0, NI_NUMERICHOST) == 0 else { return nil }
        return String(cString: hostBuf)
    }

    // MARK: - Local Network permission probe (best-effort)

    /// Starts a temporary NWListener. A policy failure while starting means the
    /// Local Network permission is missing/denied (incoming LAN connections are
    /// gated just like outgoing ones). Best-effort: on some iOS versions the
    /// listener binds even when denied; treat a failure as strong evidence and
    /// a READY as inconclusive for OUTBOUND connects (the port matrix is the
    /// authoritative gate test).
    func probeLocalNetworkPermission(timeout: TimeInterval = 5) {
        verboseLog("[minimuxer] [diag] LAN-permission: starting temporary NWListener (a system prompt may appear — tap Allow)...")
        let sem = DispatchSemaphore(value: 0)
        var result = "no state within \(Int(timeout))s (permission prompt may be pending)"
        let listener: NWListener
        do {
            listener = try NWListener(using: .tcp, on: NWEndpoint.Port(rawValue: 0)!)
        } catch {
            verboseLog("[minimuxer] [diag] LAN-permission: NWListener create failed: \(error)")
            return
        }
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                result = "READY — listener bound (permission OK, or prompt answered Allow)"
            case .failed(let err):
                result = "FAILED \(err) — if this is a policy/POSIX denial, Local Network permission is the block"
            case .waiting(let err):
                result = "WAITING \(err)"
            case .cancelled:
                result = "CANCELLED"
            @unknown default:
                return
            }
            sem.signal()
        }
        listener.start(queue: .global(qos: .utility))
        _ = sem.wait(timeout: .now() + timeout)
        listener.cancel()
        verboseLog("[minimuxer] [diag] LAN-permission listener probe: \(result)")
    }

    // MARK: - Suite

    struct ProbeSpec {
        let label: String
        let ip: String
        let port: UInt16
        let bindSource: String?
    }

    func runSuite() async {
        verboseLog("[minimuxer] [diag] ============ TUNNEL-BYPASS-DIAG DIAG-PROBE-SUITE-v1 ============")
        let os = ProcessInfo.processInfo.operatingSystemVersion
        verboseLog("[minimuxer] [diag] iOS \(os.majorVersion).\(os.minorVersion).\(os.patchVersion) — pairing loaded: \(IdeviceGateway.shared.pairingFileData != nil) — gateway peer: \(IdeviceGateway.shared.currentTunnelPeerIp ?? "nil")")

        let wifiIP = try? await NetworkIfaceScanner.shared.lanIfaceIP()
        let lan = try? await NetworkIfaceScanner.shared.probableLAN()
        let vpn = try? await NetworkIfaceScanner.shared.probableVPN()
        let utunDevice = vpn?.hostIP
        let utunPeer = vpn?.peerIP
        let gateway = lan?.gatewayCandidate
        let farEnd = lan?.farEndCandidate

        verboseLog("[minimuxer] [diag] targets: wifi=\(wifiIP ?? "nil") utun-device=\(utunDevice ?? "nil") utun-peer=\(utunPeer ?? "nil") gateway=\(gateway ?? "nil") far-end=\(farEnd ?? "nil")")

        var specs: [ProbeSpec] = []
        if let wifiIP {
            specs += [
                ProbeSpec(label: "self-wifi lockdown 62078", ip: wifiIP, port: 62078, bindSource: nil),
                ProbeSpec(label: "self-wifi rsd 49152", ip: wifiIP, port: 49152, bindSource: nil),
                ProbeSpec(label: "self-wifi closed 80", ip: wifiIP, port: 80, bindSource: nil),
                ProbeSpec(label: "self-wifi closed 443", ip: wifiIP, port: 443, bindSource: nil),
                ProbeSpec(label: "self-wifi ssh 22", ip: wifiIP, port: 22, bindSource: nil),
                ProbeSpec(label: "self-wifi lockdown bound-en0", ip: wifiIP, port: 62078, bindSource: wifiIP)
            ]
        }
        specs += [
            ProbeSpec(label: "loopback lockdown 62078", ip: "127.0.0.1", port: 62078, bindSource: nil),
            ProbeSpec(label: "loopback rsd 49152", ip: "127.0.0.1", port: 49152, bindSource: nil),
            ProbeSpec(label: "loopback closed 80", ip: "127.0.0.1", port: 80, bindSource: nil)
        ]
        if let utunPeer {
            specs += [
                ProbeSpec(label: "utun-peer lockdown 62078", ip: utunPeer, port: 62078, bindSource: nil),
                ProbeSpec(label: "utun-peer rsd 49152", ip: utunPeer, port: 49152, bindSource: nil)
            ]
        }
        if let utunDevice {
            specs += [ProbeSpec(label: "utun-device lockdown 62078", ip: utunDevice, port: 62078, bindSource: nil)]
        }
        if let gateway {
            specs += [
                ProbeSpec(label: "gateway http 80", ip: gateway, port: 80, bindSource: nil),
                ProbeSpec(label: "gateway https 443", ip: gateway, port: 443, bindSource: nil),
                ProbeSpec(label: "gateway lockdown 62078", ip: gateway, port: 62078, bindSource: nil)
            ]
        }
        if let farEnd {
            specs += [ProbeSpec(label: "far-end http 80", ip: farEnd, port: 80, bindSource: nil)]
        }

        var results: [String: Outcome] = [:]
        verboseLog("[minimuxer] [diag] --- TCP probe matrix (real errno via SO_ERROR) ---")
        for spec in specs {
            let out = probeTCP(spec.ip, port: spec.port, bindSource: spec.bindSource)
            results[spec.label] = out
            verboseLog("[minimuxer] [diag] probe \(spec.label.padding(toLength: 32, withPad: " ", startingAt: 0)) \(spec.ip):\(spec.port) -> \(out)")
        }

        verboseLog("[minimuxer] [diag] --- kernel source-address (which interface the kernel picks) ---")
        let srcTargets: [(String, String?)] = [("wifi", wifiIP), ("utun-peer", utunPeer), ("loopback", "127.0.0.1"), ("gateway", gateway)]
        for (name, ip) in srcTargets {
            guard let ip else { continue }
            let src = kernelSourceIP(destination: ip) ?? "?"
            verboseLog("[minimuxer] [diag] source-for-\(name) (\(ip)) -> \(src)")
        }

        probeLocalNetworkPermission()

        verboseLog("[minimuxer] [diag] --- VERDICT ---")
        if let self80 = results["self-wifi closed 80"]?.errnoValue {
            if self80 == EPERM {
                verboseLog("[minimuxer] [diag] VERDICT LAN-gate: self-wifi:80 = ERRNO \(self80) (EPERM) -> BLANKET LAN BLOCK -> Local Network permission likely missing/denied")
            } else if self80 == ECONNREFUSED {
                verboseLog("[minimuxer] [diag] VERDICT LAN-gate: self-wifi:80 = ERRNO \(self80) (ECONNREFUSED) -> LAN TCP ALLOWED (gate OPEN) -> EPERM on 62078 is LOCKDOWN-SPECIFIC (kernel policy on the lockdown service)")
            } else {
                verboseLog("[minimuxer] [diag] VERDICT LAN-gate: self-wifi:80 = ERRNO \(self80) -> gate state ambiguous")
            }
        } else if let gw80 = results["gateway http 80"]?.errnoValue, gw80 != EPERM {
            verboseLog("[minimuxer] [diag] VERDICT LAN-gate: gateway:80 = ERRNO \(gw80) (non-EPERM) -> LAN TCP to OTHER HOSTS ALLOWED (gate OPEN)")
        } else {
            verboseLog("[minimuxer] [diag] VERDICT LAN-gate: self:80 & gateway:80 inconclusive (EPERM on both or timeouts)")
        }

        if let loopback = results["loopback lockdown 62078"] {
            if loopback.isConnected {
                verboseLog("[minimuxer] [diag] VERDICT loopback-lockdown: 127.0.0.1:62078 CONNECTED -> lockdownd serves loopback -> running image-mounter round-trip via 127.0.0.1")
                IdeviceGateway.shared.setDiagnosticFFILogging(true)
                let r = IdeviceGateway.shared.diagProbeImageMounterVia(ip: "127.0.0.1")
                IdeviceGateway.shared.setDiagnosticFFILogging(false)
                verboseLog("[minimuxer] [diag] loopback image-mounter round-trip: \(r)")
            } else if loopback.errnoValue == EPERM {
                verboseLog("[minimuxer] [diag] VERDICT loopback-lockdown: 127.0.0.1:62078 = EPERM -> lockdownd REFUSES app connections on loopback (policy) -> no self/loopback lockdown path exists")
            } else {
                verboseLog("[minimuxer] [diag] VERDICT loopback-lockdown: 127.0.0.1:62078 -> \(loopback)")
            }
        } else {
            verboseLog("[minimuxer] [diag] VERDICT loopback-lockdown: probe result missing")
        }
        verboseLog("[minimuxer] [diag] ============ END DIAG-PROBE-SUITE ============")
    }
}
