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
private func ipv4ToUInt32(_ ipString: String) -> UInt32? {
    let components = ipString.split(separator: ".")
    guard components.count == 4,
          let b1 = UInt32(components[0]),
          let b2 = UInt32(components[1]),
          let b3 = UInt32(components[2]),
          let b4 = UInt32(components[3]) else { return nil }
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
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
        let firstHost = netBase + 1
        if firstHost != host {
            return ipv4String(firstHost)
        } else {
            return ipv4String(netBase + 2)
        }
    }

    var linkType: String {
        maskIP == "255.255.255.255" ? "p2pLink" : "subnetLink"
    }

    var networkBase: UInt32 { host & mask }
    var broadcast: UInt32 { networkBase | ~mask }

    var description: String {
        var desc = "\(name) | ip: \(hostIP) mask: \(maskIP) linkType: \(linkType)"
        if let rep = reportedPeer {
            desc += " reportedPeer: \(rep)"
        }
        if let der = derivedPeer {
            desc += " derivedPeer: \(der)"
        }
        return desc
    }
    
}

actor NetworkIfaceScanner {

    static let shared = NetworkIfaceScanner()

    private var interfacesCache: Set<NetInfo> = []
    private var connectionConfigCache: ConnectionConfigBinding?
    private var lastConnectionMode: DeviceConnectionMode? = nil
    
    // local vpn params
    var vpnIface: NetInfo?
    var derivedPeerIp: String?
    var isDerivedPeerIpReachable = false
    var overridePeerIp: String?
    var isOverridePeerIpReachable = false

    // remote server params
    var remoteServerIp: String?
    var isRemoteServerIpReachable = false
    
    private init() {}

    func bindConnectionConfig(_ binding: ConnectionConfigBinding) async {
        connectionConfigCache = binding
        // ensure started if not started already
        let connectionMode = binding.getConnectionMode()
        verboseLog("""
        [minimuxer] [iface] preferred connection mode set in binding
          • mode: .\(connectionMode) 
          • overrideTunnelPeerIp: \(binding.getOverrideTunnelPeerIp()) 
          • remoteServerIp: \(binding.getRemoteServerIp()) 
        
        """)
        await Minimuxer.network.refreshEndpoint()
    }
    
    func getPreferredConnectionMode() -> DeviceConnectionMode {
        connectionConfigCache?.getConnectionMode() ?? .notConfigured
    }

    @discardableResult
    func refresh(quietScan: Bool = false) async -> Bool {
        let connectionMode = getPreferredConnectionMode()
        defer { lastConnectionMode = connectionMode }

        switch connectionMode {
            case .notConfigured:
                debugLog("[minimuxer] [iface] connection mode not configured. skipping refresh...")
                return false
            
            case .localVPN:
                // cache last state in locals
                let lastInterfaceCache = interfacesCache
                let lastVpnIface = vpnIface
                let lastDerivedPeer = derivedPeerIp
                let lastOverrideIp = overridePeerIp
                let lastIsDerivedPeerIpReachable = isDerivedPeerIpReachable
                let lastIsOverridePeerIpReachable = isOverridePeerIpReachable
                // set new states
                interfacesCache = Self.scan(quiet: quietScan)
                vpnIface = probableVPN()
                derivedPeerIp = vpnIface?.derivedPeer
                let rawOverrideIp = connectionConfigCache?.getOverrideTunnelPeerIp()
                overridePeerIp = (rawOverrideIp?.isEmpty ?? true) ? nil : rawOverrideIp
                isDerivedPeerIpReachable = Minimuxer.shared.testDeviceConnection(ifaddr: derivedPeerIp)
                isOverridePeerIpReachable = Minimuxer.shared.testDeviceConnection(ifaddr: overridePeerIp)
            
                let isOverrideIpUnchanged = lastOverrideIp == overridePeerIp
                let isDerivedIpUnchanged = lastDerivedPeer == derivedPeerIp
                if lastConnectionMode == connectionMode &&
                    lastInterfaceCache == interfacesCache &&
                    isOverrideIpUnchanged && isDerivedIpUnchanged &&
                    lastIsDerivedPeerIpReachable == isDerivedPeerIpReachable &&
                    lastIsOverridePeerIpReachable == isOverridePeerIpReachable
                {
                    debugLog("[minimuxer] [iface] no interface state changes detected, skipping refresh")
                    return false
                }
                
                // continue updating
                debugLog("[minimuxer] [iface] using the first uTun vpn interface info")
                // set states for this mode
                // NOTE: we do not alter user configured remote override peer IP
                connectionConfigCache?.setTunnelIfaceIp(vpnIface?.hostIP)
                connectionConfigCache?.setTunnelIfaceSubnetMask(vpnIface?.maskIP)
                connectionConfigCache?.setTunnelPeerIp(derivedPeerIp)
                connectionConfigCache?.setOverrideTunnelPeerReachable(isOverridePeerIpReachable)
                // clear auto discovered reachability state
                connectionConfigCache?.setRemoteReachable(false)
            
                debugLog("""
                [minimuxer] [iface] refresh - rescan routes
                  • mode: .\(connectionMode)
                  • local iface count: \(interfacesCache.count)
                  • probable-vpn host: \(vpnIface?.hostIP ?? "nil")
                  • probable-vpn mask: \(vpnIface?.maskIP ?? "nil")
                  • probable-vpn derived peer IP: \(derivedPeerIp ?? "nil")
                  • override peer IP: \(overridePeerIp ?? "nil")
                  • override peer reachable: \(isOverridePeerIpReachable)
                
                """)
                // Since iOS 26.4 lockdown rejects device connections that arrive over the utun
                // tunnel unless the tunnel's source IP falls inside the WiFi subnet. Warn loudly
                // when the tunnel peer is outside the LAN subnet so the fix is unambiguous.
                if let lanIface = probableLAN(),
                   let peerIp = overridePeerIp ?? derivedPeerIp,
                   let peer = ipv4ToUInt32(peerIp) {
                    let peerInLANSubnet = (peer & lanIface.mask) == lanIface.networkBase
                    if !peerInLANSubnet {
                        debugLog("""
                        [minimuxer] WARNING: TUNNEL IP OUTSIDE WIFI SUBNET - tunnel peer \(peerIp) is NOT inside the WiFi subnet \(ipv4String(lanIface.networkBase) ?? "?")/\(lanIface.maskIP) (WiFi IP \(lanIface.hostIP)).
                        Since iOS 26.4, lockdown rejects device connections that arrive over the utun tunnel unless the tunnel's source IP falls inside the WiFi subnet.
                        Fix: LocalDevVPN -> Settings -> Network Configuration: set \"Tunnel IP\" and \"Device IP\" to free addresses inside this subnet (e.g. \(lanIface.hostIP) with a different last octet, or 192.168.0.200 / 192.168.0.201), keep subnet mask 255.255.255.0, then set SideStore's tunnel peer override to the new \"Device IP\", reconnect the tunnel, and force-close SideStore.
                        """)
                    }
                }

            case .remoteServer:
                let rawServerIp = connectionConfigCache?.getRemoteServerIp()
                let serverIp = (rawServerIp?.isEmpty ?? true) ? nil : rawServerIp
                let reachable = Minimuxer.shared.testDeviceConnection(ifaddr: serverIp)
                if self.lastConnectionMode == connectionMode && serverIp == remoteServerIp && reachable == isRemoteServerIpReachable {
                    debugLog("[minimuxer] [iface] no remote server state changes detected, skipping refresh")
                    return false
                }
                remoteServerIp = serverIp
                isRemoteServerIpReachable = reachable
                // set states for this mode
                // NOTE: we do not alter user configured remote server IP
                connectionConfigCache?.setRemoteReachable(reachable)
                // clear auto discovered states but not explicit override!
                connectionConfigCache?.setTunnelIfaceIp(nil)
                connectionConfigCache?.setTunnelIfaceSubnetMask(nil)
                connectionConfigCache?.setTunnelPeerIp(nil)
                connectionConfigCache?.setOverrideTunnelPeerReachable(false)
            
                debugLog("""
                [minimuxer] [iface] refresh
                  • mode: .\(connectionMode)
                  • remote server IP: \(remoteServerIp ?? "nil")
                  • remote server reachable: \(isRemoteServerIpReachable)
                
                """)

        }
        return true
    }

    private func probableVPN() -> NetInfo? {
        // TODO: @mahee96: we shouldn't return just the first coz user can have multiple uTUN lets revisit later to have a proper option
        return interfacesCache.first { $0.name.hasPrefix("utun") }
    }

    private func probableLAN() -> NetInfo? {
        return interfacesCache.first { $0.name.hasPrefix("en") }
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
        
        if !quiet {
            verboseLog(formatNetInfoList(result))
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
