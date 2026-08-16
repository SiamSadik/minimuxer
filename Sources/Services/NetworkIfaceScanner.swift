//
//  NetworkIfaceScanner.swift
//  Minimuxer
//
//  Created by ny on 2/27/26.
//  Copyright © 2026 SideStore. All rights reserved.
//


import Foundation
import Darwin

// MARK: - IPv4 helpers

@inline(__always)
private func ipv4String(_ value: UInt32) -> String? {
    var addr = in_addr(s_addr: value.bigEndian)
    var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    guard inet_ntop(AF_INET, &addr, &buf, UInt32(INET_ADDRSTRLEN)) != nil else { return nil }
    return String(cString: buf)
}

@inline(__always)
private func sockaddrIPv4(_ sa: inout sockaddr) -> UInt32? {
    var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    guard getnameinfo(&sa, socklen_t(sa.sa_len), &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0,
          let s = String(validatingUTF8: buf) else { return nil }
    var a = in_addr()
    return inet_pton(AF_INET, s, &a) == 1 ? a.s_addr.bigEndian : nil
}

// MARK: - NetInfo


internal struct NetInfo: Hashable, CustomStringConvertible, Sendable {

    let name: String
    let hostIP: String
    let maskIP: String
    let destinationIP: String?

    fileprivate let host: UInt32
    fileprivate let mask: UInt32

    init?(ifa: ifaddrs) {
        guard
            let name = String(utf8String: ifa.ifa_name),
            var addr = ifa.ifa_addr?.pointee,
            var mask = ifa.ifa_netmask?.pointee,
            let host = sockaddrIPv4(&addr),
            let maskU = sockaddrIPv4(&mask),
            let hostStr = ipv4String(host),
            let maskStr = ipv4String(maskU)
        else { return nil }

        self.name = name
        self.host = host
        self.mask = maskU
        self.hostIP = hostStr
        self.maskIP = maskStr

        let flags = Int32(ifa.ifa_flags)
        if (flags & IFF_POINTOPOINT) != 0, let dstAddr = ifa.ifa_dstaddr {
            var dst = dstAddr.pointee
            if let dstHost = sockaddrIPv4(&dst) {
                self.destinationIP = ipv4String(dstHost)
            } else {
                self.destinationIP = nil
            }
        } else {
            self.destinationIP = nil
        }
    }
    
    var reportedPeer: String? {
        destinationIP
    }

    var derivedPeer: String? {
        guard let peer = reportedPeer, peer == hostIP else { return nil }
        let netBase = host & mask
        // LocalDevVPN keeps the utun as a SELF-destination (its tunnel remote
        // address equals its own device IP), so the real peer — the fake IP
        // where the device's lockdown/RSD services listen through the tunnel —
        // is NOT the route gateway. It follows the convention device IP + 1:
        //   default:    10.7.0.0  -> 10.7.0.1
        //   in-subnet:  192.168.0.50 -> 192.168.0.51
        // The old netBase+1 rule only matched when the device IP happened to be
        // the network base (10.7.0.0/24) and derives the LAN ROUTER
        // (192.168.0.1) for in-subnet tunnels, where lockdown never listens.
        let nextHost = host + 1
        if nextHost != host {
            return ipv4String(nextHost)
        } else {
            return ipv4String(netBase + 2)
        }
    }

    var peerIP: String? {
        if let peer = reportedPeer, peer == hostIP {
            return derivedPeer
        }
        return reportedPeer
    }

    var linkType: String {
        maskIP == "255.255.255.255" ? "p2pLink" : "subnetLink"
    }

    var networkBase: UInt32 { host & mask }
    var broadcast: UInt32 { networkBase | ~mask }

    /// Likely default-gateway candidate (network base + 1) — diagnostic probes
    /// use it to test LAN TCP to OTHER hosts (Local Network permission gate).
    var gatewayCandidate: String? {
        let g = networkBase + 1
        return g == host ? nil : ipv4String(g)
    }

    /// Far end of the subnet (broadcast - 1) — another LAN-reachability probe
    /// target that usually belongs to some real device on the network.
    var farEndCandidate: String? {
        broadcast > networkBase + 1 ? ipv4String(broadcast - 1) : nil
    }

    var description: String {
        var desc = "\(name) | ip: \(hostIP) mask: \(maskIP) linkType: \(linkType)"
        if let rep = reportedPeer {
            desc += " reportedPeer: \(rep)"
        }
        if let der = derivedPeer {
            desc += " derivedPeer: \(der)"
        }
        if let peer = peerIP {
            desc += " peerIP: \(peer)"
        }
        return desc
    }
    
}

actor NetworkIfaceScanner {

    static let shared = NetworkIfaceScanner()

    private var interfacesCache: Set<NetInfo> = []
    private var refreshed = false
    private var tunnelConfigCache: TunnelConfigBinding?

    func bindTunnelConfig(_ binding: TunnelConfigBinding) async {
        tunnelConfigCache = binding
        await Minimuxer.network.refreshEndpoint()
    }


    private init() {}

    @discardableResult
    func refresh(quietScan: Bool = false) async -> Bool {
        let scannedInterfaces = Self.scan(quiet: quietScan)
        
        let isTunnelPeerInitialized = await TunnelPeer.shared.isInitialized
        if refreshed && scannedInterfaces == interfacesCache && isTunnelPeerInitialized {
            debugLog("[minimuxer] [iface] no interface changes detected, skipping scan refresh")
            return false
        }
        debugLog(formatNetInfoList(scannedInterfaces))
        
        interfacesCache = scannedInterfaces
        refreshed = true

        let vpnIface = try? probableVPN()
        tunnelConfigCache?.setTunnelIfaceIp(vpnIface?.hostIP)
        tunnelConfigCache?.setSubnetMask(vpnIface?.maskIP)
        let peerIP = vpnIface?.peerIP
        tunnelConfigCache?.setTunnelPeerIp(peerIP)
        
        debugLog("""
        [minimuxer] [iface] rescan routes
          • interfaces: \(interfacesCache.count)
          • vpn host: \(vpnIface?.hostIP ?? "nil")
          • vpn mask: \(vpnIface?.maskIP ?? "nil")
          • vpn peer: \(peerIP ?? "nil")
        """)
        return true
    }

    var interfaces: Set<NetInfo> {
        interfacesCache
    }

    private func ensureReady() throws {
        guard refreshed else { 
            throw MinimuxerInternalError.networkIfaceNotRefreshed 
        }
    }

    func probableVPN() throws -> NetInfo? {
        try ensureReady()
        // TODO: @mahee96: we shouldn't return just the first coz user can have multiple uTUN lets revisit later to have a proper option
        return interfacesCache.first { $0.name.hasPrefix("utun") }
    }

    func probableLAN() throws -> NetInfo? {
        try ensureReady()
        // Prefer en0 (Wi-Fi). Fall back to any other active en* interface with a
        // routable (non-link-local) IPv4 so USB-tethering/BridgeOS addresses
        // (169.254.x) don't win.
        if let en0 = interfacesCache.first(where: {
            $0.name == "en0" && !$0.hostIP.hasPrefix("169.254.")
        }) {
            return en0
        }
        return interfacesCache.first { $0.name.hasPrefix("en") && !$0.hostIP.hasPrefix("169.254.") }
    }

    /// The device's own routable LAN (Wi-Fi) IPv4 — used by the tunnel-bypass path
    /// to reach lockdown services over the WiFi interface instead of the utun tunnel.
    func lanIfaceIP() throws -> String? {
        try probableLAN()?.hostIP
    }

    // MARK: scan
    static func scan(quiet: Bool = false) -> Set<NetInfo> {
        if !quiet{
            debugLog("[minimuxer] [iface] scan requested...")
        }
        
        var result = Set<NetInfo>()
        var head: UnsafeMutablePointer<ifaddrs>? = nil
        guard getifaddrs(&head) == 0, let first = head else { return result }
        defer { freeifaddrs(head) }

        var cur: UnsafeMutablePointer<ifaddrs>? = first
        while let p = cur {
            let e = p.pointee
            let flags = Int32(e.ifa_flags)

            let ipv4 = e.ifa_addr?.pointee.sa_family == UInt8(AF_INET)
            let active = (flags & (IFF_UP | IFF_RUNNING | IFF_LOOPBACK)) == (IFF_UP | IFF_RUNNING)

            if ipv4, active, let info = NetInfo(ifa: e) {
                result.insert(info)
            }
            cur = e.ifa_next
        }
        
        if !quiet{
            debugLog("[minimuxer] [iface] total: \(result.count)")
        }
        return result
    }

}

// MARK: - Logging Helpers

fileprivate func formatNetInfoList(_ list: Set<NetInfo>) -> String {
    let maxNameLength = list.map { $0.name.count }.max() ?? 0
    let maxIPLength = list.map { $0.hostIP.count }.max() ?? 0
    return "[minimuxer] [iface] local interfaces list:\n" +
        "---------------------------------------------------\n" +
        list.map { info -> String in
            let paddedName = info.name.padding(toLength: maxNameLength, withPad: " ", startingAt: 0)
            let paddedIP = info.hostIP.padding(toLength: maxIPLength, withPad: " ", startingAt: 0)
            return "  • \(paddedName) ip: \(paddedIP) : \(info.maskIP)"
        }.sorted().joined(separator: "\n") + "\n" +
        "---------------------------------------------------"
}
