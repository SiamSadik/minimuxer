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

            // TUNNEL BYPASS: reach lockdown services over the device's OWN WiFi IP
            // instead of the utun tunnel peer. Since iOS 26.4, lockdown rejects
            // connections that arrive over the tunnel unless the source IP falls
            // inside the WiFi subnet; a self-connection to our own WiFi IP keeps the
            // source inside the subnet and never touches the utun at all. Works with
            // the App Store LocalDevVPN at its DEFAULT config (10.7.0.0 / 10.7.0.1)
            // and a fresh pairing file — no VPN settings changes required.
            if let lanIP = try? await NetworkIfaceScanner.shared.lanIfaceIP(),
               Minimuxer.shared.testDeviceConnection(ifaddr: lanIP) {
                verboseLog("[minimuxer] [net] TUNNEL BYPASS active — targeting device's own WiFi IP \(lanIP) for lockdown services (utun peer \(peerIP ?? "nil") ignored)")
                await apply(lanIP)
            } else {
                let reason = (try? await NetworkIfaceScanner.shared.lanIfaceIP())
                    .map { "own WiFi IP \($0) not reachable" }
                    ?? "no routable WiFi (en*) interface found"
                verboseLog("[minimuxer] [net] TUNNEL BYPASS not available (\(reason)) — falling back to utun peer \(peerIP ?? "nil")")
                await apply(peerIP)
            }
        } else {
            verboseLog("[minimuxer] [net] no SideVPN endpoint detected")
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
