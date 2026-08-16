//
//  EmbeddedTunnelService.swift
//  Minimuxer
//
//  Created for the in-IPA tunnel experiment (2026-08-16).
//  Copyright © 2026 SideStore. All rights reserved.
//

import Foundation
import NetworkExtension

/// Brings up the packet-tunnel provider EMBEDDED in the host app (LiveContainer),
/// so SideStore gets an in-subnet utun tunnel without the separate LocalDevVPN
/// app — the only configuration that satisfies the iOS 26.4+/27 lockdown
/// source-IP check (source inside the WiFi subnet AND not one of the device's
/// own addresses).
///
/// The embedded provider is the LocalDevVPN-style PacketTunnelProvider with the
/// /32-route fix: utun address = <wifiIP+1>, peer (fake IP) = <wifiIP+2>, so
/// lockdownd sees connections from <wifiIP+2> (in-subnet, not-self) and the
/// anti-self + source-IP checks both pass.
///
/// This service only works when BOTH hold:
///   1. the host app actually contains a `com.apple.networkextension.packet-tunnel`
///      app extension (bundled into LiveContainer.app/PlugIns), and
///   2. the app was signed WITH the Network Extensions entitlement
///      (com.apple.developer.networking.networkextension) — only possible via
///      the custom `iloader-ne` signing tool, since free-account iLoader never
///      registers that capability.
/// Otherwise it is a clean no-op and SideStore behaves exactly as before
/// (external VPN, e.g. LocalDevVPN).
final internal class EmbeddedTunnelService: @unchecked Sendable {

    static let shared = EmbeddedTunnelService()

    /// Set true when this run actually started (or found already connected)
    /// the embedded tunnel, so callers know to re-derive the peer endpoint.
    private(set) var didStart = false

    private static let utunAddressOffset: UInt32 = 1   // utun address = wifiIP + 1
    private static let peerAddressOffset: UInt32 = 2   // peer (fake IP) = wifiIP + 2
    private static let subnetMask = "255.255.255.0"

    private init() {}

    /// The bundle identifier of the host app's packet-tunnel provider, resolved
    /// at runtime so the team-ID suffix that iLoader appends
    /// (com.kdt.livecontainer.<TEAMID>.TunnelProv) is handled automatically.
    func packetTunnelProviderBundleID() -> String? {
        guard let plugIns = Bundle.main.builtInPlugInsURLs else { return nil }
        for url in plugIns where url.pathExtension == "appex" {
            guard let info = Bundle(url: url)?.infoDictionary else { continue }
            guard let ext = info["NSExtension"] as? [String: Any],
                  let point = ext["NSExtensionPointIdentifier"] as? String,
                  point == "com.apple.networkextension.packet-tunnel" else { continue }
            let bundleID = info["CFBundleIdentifier"] as? String
            verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: found embedded packet-tunnel provider bundle: \(bundleID ?? "?")")
            return bundleID
        }
        return nil
    }

    func startIfAvailable() async {
        didStart = false

        guard let providerBundleID = packetTunnelProviderBundleID() else {
            verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: no embedded packet-tunnel extension found in this app — skipping (external VPN only)")
            return
        }

        guard let wifiIP = try? await NetworkIfaceScanner.shared.lanIfaceIP() else {
            verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: no WiFi (en0) IP available yet — skipping")
            return
        }
        guard let tunnelIP = Self.adding(wifiIP, offset: Self.utunAddressOffset),
              let peerIP = Self.adding(wifiIP, offset: Self.peerAddressOffset) else {
            verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: could not compute in-subnet IPs from \(wifiIP) — skipping")
            return
        }

        verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: configuring utun=\(tunnelIP) peer=\(peerIP) (wifi \(wifiIP)) via \(providerBundleID)")

        let manager: NETunnelProviderManager
        let isNewManager: Bool
        do {
            let existing = try await NETunnelProviderManager.loadAllFromPreferences()
            if let found = existing.first(where: {
                ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == providerBundleID
            }) {
                manager = found
                isNewManager = false
            } else {
                manager = NETunnelProviderManager()
                isNewManager = true
            }
        } catch {
            verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: NETunnelProviderManager unavailable (\(error.localizedDescription)) — the app was NOT signed with the Network Extensions entitlement; embedded tunnel cannot start (falling back to external VPN)")
            return
        }

        let protocolConfiguration = NETunnelProviderProtocol()
        protocolConfiguration.providerBundleIdentifier = providerBundleID
        protocolConfiguration.serverAddress = peerIP
        protocolConfiguration.providerConfiguration = [
            "TunnelDeviceIP": tunnelIP,
            "TunnelFakeIP": peerIP,
            "SubnetMask": Self.subnetMask,
        ]

        manager.protocolConfiguration = protocolConfiguration
        manager.localizedDescription = "SideStore Embedded Tunnel"
        manager.isEnabled = true

        // Already connected (e.g. re-boot while the VPN profile persists)? Nothing to do.
        if manager.connection.status == .connected || manager.connection.status == .connecting {
            verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: already connected/connecting (status \(manager.connection.status.rawValue))")
            didStart = true
            await waitForUTun(tunnelIP: tunnelIP)
            return
        }

        do {
            try await manager.saveToPreferences()
        } catch {
            verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: saveToPreferences failed (\(error.localizedDescription)) — Network Extensions entitlement missing? falling back to external VPN")
            return
        }

        do {
            try manager.connection.startVPNTunnel()
        } catch {
            verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: startVPNTunnel failed (\(error.localizedDescription)) — another VPN may be active (disconnect LocalDevVPN first); falling back to external VPN")
            return
        }

        verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: start requested (\(isNewManager ? "new" : "existing") manager) — waiting for utun...")
        didStart = true
        await waitForUTun(tunnelIP: tunnelIP)
    }

    /// Poll the interface list until a utun carrying `tunnelIP` appears
    /// (bounded, ~20s), then hand back so the caller re-derives the peer.
    private func waitForUTun(tunnelIP: String) async {
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline {
            let found = NetworkIfaceScanner.scan(quiet: true).contains {
                $0.name.hasPrefix("utun") && $0.hostIP == tunnelIP
            }
            if found {
                verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: utun UP with \(tunnelIP) — embedded tunnel active")
                return
            }
            try? await Task.sleep(nanoseconds: 500_000_000)
        }
        verboseLog("[minimuxer] [tunnel] IN-IPA TUNNEL: timed out waiting for utun \(tunnelIP)")
    }

    private static func adding(_ ip: String, offset: UInt32) -> String? {
        let parts = ip.split(separator: ".").compactMap { UInt32($0) }
        guard parts.count == 4 else { return nil }
        var value = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        value &+= offset
        return "\(value >> 24 & 0xFF).\(value >> 16 & 0xFF).\(value >> 8 & 0xFF).\(value & 0xFF)"
    }
}
