//
//  NetworkObserverService.swift
//  Minimuxer
//
//  Original Rust Implementation by @jkcoxson
//  Swift Port created by Magesh K on 02/03/26.
//

import Network
import Foundation

final internal class NetworkObserverService: NetworkObserverAPI, @unchecked Sendable {

    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "net.monitor")
    private let state = State()
    
    private actor State {
        var started = false
        var observationTask: Task<Void, Never>? = nil
        
        func with<T>(_ body: (isolated State) throws -> T) rethrows -> T {
            try body(self)
        }
    }

    @discardableResult
    func start() async -> Bool {
        let alreadyStarted = await state.with { $0.started }
        guard !alreadyStarted else {
            verboseLog("[minimuxer] [net] monitor already started")
            return false
        }

        await state.with { $0.started = true }
        verboseLog("[minimuxer] [net] monitor started")

        let paths = AsyncStream<NWPath> { [weak self] continuation in
            guard let self = self else {
                continuation.finish()
                return
            }
            self.monitor.pathUpdateHandler = { path in
                continuation.yield(path)
            }
        }

        self.monitor.start(queue: self.queue)

        let task = Task.detached { [weak self] in
            for await path in paths {
                verboseLog("[minimuxer] [net] path changed, status: \(path.status)")
                guard path.status == .satisfied else { continue }
                await self?.refreshEndpoint()
            }
        }
        await state.with { $0.observationTask = task }

        return true
    }
    
    func refreshEndpoint() async {
        verboseLog("[minimuxer] [net] refreshing interfaces list and peers")
        let changed = await NetworkIfaceScanner.shared.refresh()
        guard changed else { return }

        verboseLog("[minimuxer] [net] retrive the first uTun vpn interface info")
        if let info = try? await NetworkIfaceScanner.shared.probableVPN() {
            let peerIP = info.peerIP
            verboseLog("""
            [minimuxer] [net] vpn interface detected
              • name: \(info.name)
              • ip: \(info.hostIP)
              • mask: \(info.maskIP)
              • linkType: \(info.linkType)
              • reportedPeer: \(info.reportedPeer ?? "nil")
              • derivedPeer: \(info.derivedPeer ?? "nil")
              • activePeer: \(peerIP ?? "nil")
            """)

            func apply(_ endpoint: String?) async {
                if let endpoint {
                    verboseLog("[minimuxer] [net] update device endpoint: \(endpoint)")
                    await TunnelPeer.shared.update(endpoint)
                    MuxerService.notifyDeviceAttached(tunnelPeerIp: endpoint)
                } else {
                    verboseLog("[minimuxer] [net] peer not available for \(info.name)")
                    await TunnelPeer.shared.clear()
                    MuxerService.notifyDeviceDetached()
                }
            }

            // SOURCE-BIND FIX (replaces the tunnel-bypass experiment): the on-device
            // probe matrix proved lockdownd 62078 is EPERM on EVERY local address
            // (own WiFi IP, loopback, utun device IP) and reachable ONLY at the utun
            // peer 10.7.0.1 — so the WiFi-IP bypass was aimed at a dead listener.
            // The old broken-pipe happened AFTER the TCP accept: lockdownd accepts
            // the connection over the utun, then the iOS 26.4+ source-IP check kills
            // the session because the source seen by lockdownd (the device's own
            // utun address, 10.7.0.0) is NOT inside the WiFi subnet (192.168.0.0/24).
            // FIX: keep the destination at the utun peer but BIND the socket source
            // to the device's own WiFi IP (inside the subnet) via a local relay —
            // the FFI connects to 127.0.0.1:62078, the relay opens a source-bound
            // socket to 10.7.0.1:62078 and splices bytes. No router / VPN changes.
            // RSD-BYPASS: stash the device's own WiFi IP for IdeviceGateway's
            // RemotePairing endpoint selection (RSD 49152 accepts app
            // connections there; lockdown 62078 does not).
            IdeviceGateway.rsdBypassCandidate = try? await NetworkIfaceScanner.shared.lanIfaceIP()

            if EmbeddedTunnelService.shared.didStart {
                // IN-IPA (embedded in-subnet) tunnel: connect DIRECTLY to the utun
                // peer. The source-bind relay would hand lockdownd the device's OWN
                // WiFi IP as the connection source — the anti-self half of the iOS
                // 26.4+ check kills that. Only the direct path's post-rewrite source
                // (wifiIP + 2) is both inside the WiFi subnet AND not one of the
                // device's own addresses, so both halves of the check pass.
                verboseLog("[minimuxer] [net] IN-IPA TUNNEL active — connecting directly to utun peer \(peerIP ?? "nil") (source-bind relay skipped)")
                LockdownSourceRelay.stop()
                await apply(peerIP)
            } else if let lanIP = IdeviceGateway.rsdBypassCandidate,
                      let peerIP,
                      LockdownSourceRelay.start(source: lanIP, upstream: peerIP) {
                verboseLog("[minimuxer] [net] SOURCE-BIND RELAY active — lockdown via 127.0.0.1:62078 -> \(peerIP ?? "?") with source bound to \(lanIP) (inside WiFi subnet)")
                await apply("127.0.0.1")
            } else {
                let lanIP = try? await NetworkIfaceScanner.shared.lanIfaceIP()
                let reason = LockdownSourceRelay.lastFailure
                    ?? lanIP.map { "own WiFi IP \($0) unavailable for source bind" }
                    ?? "no routable WiFi (en*) interface found"
                verboseLog("[minimuxer] [net] SOURCE-BIND relay not available (\(reason)) — falling back to utun peer \(peerIP ?? "nil")")
                LockdownSourceRelay.stop()
                await apply(peerIP)
            }
        } else {
            verboseLog("[minimuxer] [net] no SideVPN endpoint detected")
            LockdownSourceRelay.stop()
            await TunnelPeer.shared.clear()
            MuxerService.notifyDeviceDetached()
        }
    }
    
    @discardableResult
    func stop() async -> Bool {
        let isStarted = await state.with { $0.started }
        guard isStarted else {
            verboseLog("[minimuxer] [net] monitor already stopped")
            return false
        }

        self.monitor.cancel()
        await state.with {
            $0.observationTask?.cancel()
            $0.observationTask = nil
            $0.started = false
        }
        
        verboseLog("[minimuxer] [net] monitor stopped")
        return true
    }
    
    var isWifiSatisfied: Bool {
        let path = monitor.currentPath
        return path.status == .satisfied && path.usesInterfaceType(.wifi)
    }
    
    var isWiredSatisfied: Bool {
        let path = monitor.currentPath
        return path.status == .satisfied && path.usesInterfaceType(.wiredEthernet)
    }
    
    var isUsbSatisfied: Bool {
        return NetworkIfaceScanner.scan(quiet: true).contains { info in
            let name = info.name.lowercased()
            return name.hasPrefix("en") && name != "en0" && info.hostIP.hasPrefix("169.254.")
        }
    }
    
    var isBridgeSatisfied: Bool {
        let path = monitor.currentPath
        if path.status == .satisfied && path.usesInterfaceType(.other) {
            return true
        }
        
        return NetworkIfaceScanner.scan(quiet: true).contains { info in
            info.name.lowercased().contains("bridge") ||
            info.name.lowercased().contains("ap")
        }
    }

    // True when at least one `utun*` interface is active (userspace VPN — ex: wireguard).
    var isUTunAvailable: Bool {
        return NetworkIfaceScanner.scan(quiet: true).contains { $0.name.hasPrefix("utun") }
    }

    // True when at least one `ipsec*` interface is active (IKEv2/IPSec kernel VPN).
    var isIKEv2IPSecAvailable: Bool {
        return NetworkIfaceScanner.scan(quiet: true).contains { $0.name.hasPrefix("ipsec") }
    }
}
