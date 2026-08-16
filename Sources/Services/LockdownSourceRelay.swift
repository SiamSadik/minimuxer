//
//  LockdownSourceRelay.swift
//  Minimuxer
//
//  Source-bind lockdown relay for the iOS 26.4+ lockdown source-IP check.
//
//  What the on-device probe matrix proved (tunnel-sourcefix diag log):
//    - lockdownd 62078 is EPERM on EVERY local address (own WiFi IP, loopback,
//      utun device IP) and is reachable ONLY at the utun peer (10.7.0.1) —
//      the tunnel-bypass target (the device's own WiFi IP) was a dead listener.
//    - RSD 49152 is reachable from everywhere (WiFi IP, loopback, utun peer).
//    - The old broken-pipe happened AFTER the TCP accept: lockdownd accepts
//      the connection over the utun, then the iOS 26.4+ source-IP check kills
//      the session because the source seen by lockdownd (the device's own
//      utun address, 10.7.0.0) is NOT inside the WiFi subnet (192.168.0.0/24).
//
//  The fix: keep the destination at the utun peer (where lockdownd actually
//  listens) but BIND the outbound socket's source address to the device's own
//  WiFi IP (192.168.0.189), which IS inside the WiFi subnet. The FFI connects
//  to 127.0.0.1:62078 (tunnel peer set to 127.0.0.1); this relay accepts that
//  connection, opens a socket with SOURCE bound to the WiFi IP, connects it to
//  the utun peer 10.7.0.1:62078, and splices bytes in both directions. To
//  lockdownd the connection now arrives with an in-subnet source -> the
//  source-IP check passes -> DDI can mount and refresh can complete.
//

import Foundation
import Darwin

final class LockdownSourceRelay {

    static private(set) var isListening = false

    private static var listenSocket: Int32 = -1
    private static var serverThread: Thread? = nil
    private static var upstreamIP: String? = nil
    private static var sourceIP: String? = nil

    // MARK: - Lifecycle

    @discardableResult
    static func start(source: String, upstream: String, port: UInt16 = MinimuxerConstants.lockdowndPort) -> Bool {
        stop()

        upstreamIP = upstream
        sourceIP = source

        verboseLog("[minimuxer] [relay] SOURCE-BIND RELAY starting — 127.0.0.1:\(port) -> \(upstream):\(port) with source bound to \(source)")

        let thread = Thread {
            listenLoop(port: port)
        }
        thread.name = "LockdownSourceRelay"
        thread.qualityOfService = .userInitiated
        thread.start()
        serverThread = thread

        let deadline = Date().addingTimeInterval(2.0)
        while Date() < deadline {
            if isListening { return true }
            usleep(50_000)
        }
        return isListening
    }

    static func stop() {
        serverThread?.cancel()
        if listenSocket >= 0 {
            shutdown(listenSocket, SHUT_RDWR)
            close(listenSocket)
            listenSocket = -1
        }
        isListening = false
        serverThread = nil
    }

    // MARK: - Listener

    private static func listenLoop(port: UInt16) {
        while !Thread.current.isCancelled {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else {
                usleep(500_000)
                continue
            }

            var yes = 1
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int>.size))
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))

            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = port.bigEndian
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")

            let bindResult = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard bindResult == 0, listen(fd, 16) == 0 else {
                debugLog("[minimuxer] [relay] WARN: bind/listen 127.0.0.1:\(port) failed (errno=\(errno))")
                close(fd)
                usleep(500_000)
                continue
            }

            listenSocket = fd
            isListening = true
            verboseLog("[minimuxer] [relay] SOURCE-BIND RELAY listening on 127.0.0.1:\(port)")

            // Self-test: verify the source-bound upstream connect works once, so the
            // log has an immediate socket-level verdict before any FFI service call.
            if let up = upstreamIP, let src = sourceIP {
                let r = testUpstream(source: src, upstream: up, port: port)
                verboseLog("[minimuxer] [relay] SELF-TEST upstream \(up):\(port) source \(src) -> \(r)")
            }

            while !Thread.current.isCancelled {
                var clientAddr = sockaddr()
                var addrLen = socklen_t(MemoryLayout<sockaddr>.size)
                let clientFd = accept(fd, &clientAddr, &addrLen)
                guard clientFd >= 0 else {
                    if errno == EBADF { break }
                    usleep(100_000)
                    continue
                }

                var nosig = 1
                setsockopt(clientFd, SOL_SOCKET, SO_NOSIGPIPE, &nosig, socklen_t(MemoryLayout<Int32>.size))

                let up = upstreamIP ?? ""
                let src = sourceIP ?? ""
                Thread.detachNewThread {
                    handleClient(client: clientFd, source: src, upstream: up, port: port)
                }
            }

            close(fd)
            listenSocket = -1
            isListening = false
            usleep(500_000)
        }
    }

    // MARK: - Upstream

    private static func testUpstream(source: String, upstream: String, port: UInt16) -> String {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return "socket errno=\(errno)" }
        defer { close(fd) }

        if !source.isEmpty {
            var saddr = sockaddr_in()
            saddr.sin_family = sa_family_t(AF_INET)
            saddr.sin_port = 0
            guard inet_pton(AF_INET, source, &saddr.sin_addr) == 1 else { return "inet_pton \(source) failed" }
            let br = withUnsafePointer(to: &saddr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            if br != 0 { return "bind \(source) errno=\(errno) (\(String(cString: strerror(errno))))" }
        }

        var daddr = sockaddr_in()
        daddr.sin_family = sa_family_t(AF_INET)
        daddr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, upstream, &daddr.sin_addr) == 1 else { return "inet_pton \(upstream) failed" }
        let cr = withUnsafePointer(to: &daddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if cr != 0 { return "connect errno=\(errno) (\(String(cString: strerror(errno))))" }
        return "OK"
    }

    private static func handleClient(client: Int32, source: String, upstream: String, port: UInt16) {
        let up = socket(AF_INET, SOCK_STREAM, 0)
        guard up >= 0 else {
            close(client)
            return
        }

        var nosig = 1
        setsockopt(up, SOL_SOCKET, SO_NOSIGPIPE, &nosig, socklen_t(MemoryLayout<Int32>.size))

        defer {
            close(up)
            close(client)
        }

        // Bind the source to the device's own WiFi IP (inside the LAN subnet).
        if !source.isEmpty {
            var saddr = sockaddr_in()
            saddr.sin_family = sa_family_t(AF_INET)
            saddr.sin_port = 0
            if inet_pton(AF_INET, source, &saddr.sin_addr) == 1 {
                let br = withUnsafePointer(to: &saddr) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        bind(up, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                    }
                }
                if br != 0 {
                    verboseLog("[minimuxer] [relay] upstream bind \(source) errno=\(errno) (\(String(cString: strerror(errno))))")
                }
            }
        }

        var daddr = sockaddr_in()
        daddr.sin_family = sa_family_t(AF_INET)
        daddr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, upstream, &daddr.sin_addr) == 1 else { return }

        let cr = withUnsafePointer(to: &daddr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(up, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard cr == 0 else {
            verboseLog("[minimuxer] [relay] upstream connect \(upstream):\(port) source \(source) -> errno=\(errno) (\(String(cString: strerror(errno))))")
            return
        }

        verboseLog("[minimuxer] [relay] upstream connect \(upstream):\(port) source \(source) -> OK — splicing")
        splice(a: client, b: up)
    }

    // MARK: - Splice

    private static func splice(a: Int32, b: Int32) {
        var closed = false
        while !closed {
            var pfds = [
                pollfd(fd: a, events: Int16(POLLIN), revents: 0),
                pollfd(fd: b, events: Int16(POLLIN), revents: 0)
            ]
            let pr = poll(&pfds, 2, -1)
            if pr <= 0 { break }

            for (i, pfd) in pfds.enumerated() {
                if (pfd.revents & Int16(POLLIN)) != 0 {
                    let from = i == 0 ? a : b
                    let to = i == 0 ? b : a
                    var buf = [UInt8](repeating: 0, count: 16384)
                    let n = recv(from, &buf, buf.count, 0)
                    if n <= 0 { closed = true; break }
                    var off = 0
                    while off < n {
                        let s = buf.withUnsafeBytes { ptr in
                            send(to, ptr.baseAddress!.advanced(by: off), n - off, 0)
                        }
                        if s <= 0 { closed = true; break }
                        off += s
                    }
                } else if (pfd.revents & Int16(POLLERR | POLLHUP | POLLNVAL)) != 0 {
                    closed = true
                    break
                }
            }
        }
        shutdown(a, SHUT_RDWR)
        shutdown(b, SHUT_RDWR)
    }
}
