// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/discovery.go
// Purpose : LAN discovery of the master by UDP broadcast (bootstrap only, never trusted alone)
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strconv"
	"time"
)

// Discovered is the answer of a master to a DISCOVER broadcast.
type Discovered struct {
	Host          string
	WebPort       int    `json:"web_port"`
	AgentPort     int    `json:"agent_port"`
	CAFingerprint string `json:"ca_fingerprint"`
	Version       string `json:"version"`
	Type          string `json:"type"`
}

// broadcastAddresses returns the limited broadcast address and the directed broadcast
// address of every up, broadcast-capable IPv4 interface.
func broadcastAddresses() []net.IP {
	result := []net.IP{net.IPv4bcast}
	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagBroadcast == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue
			}
			ip := ipnet.IP.To4()
			mask := net.IP(ipnet.Mask).To4()
			if mask == nil {
				continue
			}
			bcast := make(net.IP, 4)
			for i := range ip {
				bcast[i] = ip[i] | ^mask[i]
			}
			result = append(result, bcast)
		}
	}
	return result
}

// Discover broadcasts DISCOVER and returns the first valid MASTER answer.
func Discover(ctx context.Context, port int, timeout time.Duration) (*Discovered, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := enableBroadcast(conn); err != nil {
		logger.Debug("cannot enable SO_BROADCAST", "error", err)
	}
	payload, _ := json.Marshal(map[string]any{"type": "DISCOVER", "version": version})
	for _, ip := range broadcastAddresses() {
		if _, err := conn.WriteToUDP(payload, &net.UDPAddr{IP: ip, Port: port}); err != nil {
			logger.Debug("discovery send failed", "to", ip.String(), "error", err)
		}
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetReadDeadline(deadline)
	buf := make([]byte, 2048)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil, errors.New("no master answered the discovery broadcast on UDP port " + strconv.Itoa(port))
		}
		var d Discovered
		if json.Unmarshal(buf[:n], &d) != nil || d.Type != "MASTER" || d.WebPort == 0 || d.AgentPort == 0 {
			continue
		}
		d.Host = from.IP.String()
		logger.Info("master discovered", "host", d.Host, "version", d.Version)
		return &d, nil
	}
}
