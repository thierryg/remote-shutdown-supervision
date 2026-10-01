// =============================================================================
// Remote Shutdown - LAN parental control and machine management (master/agent)
// -----------------------------------------------------------------------------
// File    : agent/sysinfo.go
// Purpose : System facts: network interfaces, uptime since boot or last resume, OS description
// Author  : Thierry Gayet <thierry.gayet@labworks.fr>
// Project : remote-shutdown (version: VERSION)
// Copyright (c) 2026 Thierry Gayet. SPDX-License-Identifier: 0BSD
// =============================================================================

package main

import (
	"net"
	"runtime"
	"sort"
	"sync"
	"time"
)

// NetIfInfo describes one network interface in DECLARE / UPDATE messages.
type NetIfInfo struct {
	Name string   `json:"name"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
	MAC  string   `json:"mac"`
}

// Interfaces returns the up, non-loopback interfaces that have at least one address.
func Interfaces() []NetIfInfo {
	result := []NetIfInfo{}
	ifaces, err := net.Interfaces()
	if err != nil {
		return result
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		info := NetIfInfo{Name: iface.Name, MAC: iface.HardwareAddr.String(), IPv4: []string{}, IPv6: []string{}}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			if ipnet.IP.To4() != nil {
				info.IPv4 = append(info.IPv4, ipnet.IP.String())
			} else {
				info.IPv6 = append(info.IPv6, ipnet.IP.String())
			}
		}
		if len(info.IPv4)+len(info.IPv6) == 0 {
			continue
		}
		sort.Strings(info.IPv4)
		sort.Strings(info.IPv6)
		result = append(result, info)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

// resumeTracker detects sleep / hibernation (including the Windows "fast startup" hybrid
// shutdown) by comparing the wall clock with a clock that stops while the system sleeps.
type resumeTracker struct {
	mu         sync.Mutex
	lastWall   time.Time
	lastAwake  time.Duration
	resumedAt  time.Time
	started    bool
	sampleOnce sync.Once
}

var resume resumeTracker

// suspendGap is the minimum unexplained wall-clock jump considered a resume.
const suspendGap = 2 * time.Minute

// sample records the clocks and detects a resume since the previous sample.
func (r *resumeTracker) sample() {
	r.mu.Lock()
	defer r.mu.Unlock()
	wall, awake := time.Now().Round(0), awakeClock()
	if r.started {
		if wall.Sub(r.lastWall)-(awake-r.lastAwake) > suspendGap {
			r.resumedAt = wall
			logger.Info("resume from sleep detected: uptime counter restarted")
		}
	}
	r.lastWall, r.lastAwake, r.started = wall, awake, true
}

// start samples the clocks every 15 seconds for the lifetime of the process.
func (r *resumeTracker) start() {
	r.sampleOnce.Do(func() {
		r.sample()
		go func() {
			for range time.Tick(15 * time.Second) {
				r.sample()
			}
		}()
	})
}

// Uptime returns the time since boot or since the last resume from sleep, whichever is
// shorter: this is the "machine in use" time the parental-control limit applies to.
func Uptime() time.Duration {
	resume.start()
	up := bootUptime()
	resume.mu.Lock()
	resumedAt := resume.resumedAt
	resume.mu.Unlock()
	if !resumedAt.IsZero() {
		if since := time.Since(resumedAt); since < up {
			return since
		}
	}
	return up
}

// osDescription returns a human-readable OS name (e.g. "Ubuntu 24.04.1 LTS", "macOS 15.1").
func osDescription() string {
	if d := platformOSName(); d != "" {
		return d
	}
	return runtime.GOOS
}
