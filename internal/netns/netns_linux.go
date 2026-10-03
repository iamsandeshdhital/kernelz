//go:build linux

// Package netns builds the container's half of a virtual network cable.
//
// A network namespace is useless until a veth pair has one end moved into it.
// A veth pair is two virtual network interfaces that behave as if a cable ran
// between them: whatever enters one comes out the other. The host end attaches
// to a bridge, the container end lives inside the container's namespace.
//
// The asymmetry is the interesting part. The container is *born* inside its
// network namespace, so from inside it the host's network is unreachable --
// which is the entire point of the isolation. Therefore the veth end has to be
// pushed into the container from the outside, after the container process
// exists: /proc/<pid>/ns/net is opened and the peer is attached to that fd.
//
// Nothing in this package has been executed against a real kernel. It compiles
// and is structurally reviewed; treat it as unverified.
package netns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"unsafe"
)

// ---------------------------------------------------------------------------
// netlink plumbing
// ---------------------------------------------------------------------------

const (
	nlFamilies = 0 // AF_UNSPEC
	nlRoute    = 0 // NETLINK_ROUTE

	// Message types.
	msgNewLink = 16 // RTM_NEWLINK
	msgDelLink = 17 // RTM_DLINK
	msgNewAddr = 20 // RTM_NEWADDR
	msgGetLink = 18 // RTM_GETLINK

	nlFlagsRequest = 0x01
	nlFlagsAck     = 0x04

	nlAlignTo = 4
)

// ifinfomsg payload that follows a link message header.
type ifInfomsg struct {
	Family uint8
	_      uint8
	Type   uint16
	Index  int32
	Flags  uint32
	Change uint32
}

// rtmsg payload for address messages.
type rtmsg struct {
	Family   uint8
	DstLen   uint8
	SrcLen   uint8
	Tos      uint8
	Table    uint8
	Protocol uint8
	Scope    uint8
	Type     uint8
	Flags    uint32
}

// ifinfomsg.Flags values.
const (
	iffUp   = 0x1
	iffEcho = 0x8
)

// rtattr is the netlink attribute header.
type rtattr struct {
	Len  uint16
	Type uint16
}

func align(n int) int { return (n + nlAlignTo - 1) &^ (nlAlignTo - 1) }

// attr appends a netlink attribute with its 4-byte alignment padding.
func attr(b []byte, typ uint16, data []byte) []byte {
	l := 4 + len(data)
	b = append(b, make([]byte, 4)...)
	binary.LittleEndian.PutUint16(b[len(b)-4:], uint16(l))
	binary.LittleEndian.PutUint16(b[len(b)-2:], typ)
	b = append(b, data...)
	if pad := align(l) - l; pad > 0 {
		b = append(b, make([]byte, pad)...)
	}
	return b
}

// attrString appends a NUL-terminated string attribute.
func attrString(b []byte, typ uint16, s string) []byte {
	return attr(b, typ, append([]byte(s), 0))
}

// attrU32 appends a 32-bit attribute.
func attrU32(b []byte, typ uint16, v uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, v)
	return attr(b, typ, buf)
}

// attrNested opens a nested attribute container and returns the buffer plus the
// offset at which its length must be filled in once the contents are known.
func attrNested(b []byte, typ uint16) ([]byte, int) {
	start := len(b)
	b = attr(b, typ, nil)
	return b, start
}

// closeNested back-fills the length of a nested attribute opened earlier.
func closeNested(b []byte, start int) []byte {
	nested := b[start+4:]
	// Length includes the attribute header.
	binary.LittleEndian.PutUint16(b[start:], uint16(len(nested)+4))
	return b
}

// rtattr types used here, from include/uapi/linux/rtnetlink.h.
const (
	iflaIfName    = 3
	iflaLinkInfo  = 18
	iflaNetNsFd   = 28
	iflaInfoKind  = 1
	iflaInfoData  = 2
	vethInfoPeer  = 1
	ifaLocal      = 2
	ifaAddress    = 3
	ifaBroadcast  = 4
	ifaLocalLabel = 10
)

// netlinkConn is a bound NETLINK_ROUTE socket.
type netlinkConn struct {
	fd  int
	seq uint32
}

func dialNetlink() (*netlinkConn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, nlRoute)
	if err != nil {
		return nil, fmt.Errorf("netlink: socket: %w", err)
	}
	// netlink_rtmmsg has a 4-byte pad between fields, hence the odd size.
	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Bind(fd, lsa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink: bind: %w", err)
	}
	return &netlinkConn{fd: fd, seq: 1}, nil
}

func (c *netlinkConn) Close() error { return syscall.Close(c.fd) }

// request sends a message and, for a non-dump request, waits for the ACK.
func (c *netlinkConn) request(msg []byte) error {
	lsa := &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}
	if err := syscall.Sendto(c.fd, msg, 0, lsa); err != nil {
		return fmt.Errorf("netlink: send: %w", err)
	}

	buf := make([]byte, 8192)
	for {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("netlink: recv: %w", err)
		}
		if n < 16 {
			continue
		}
		mtype := binary.LittleEndian.Uint16(buf[4:])
		if mtype == 2 { // NLMSG_ERROR
			if n < 20 {
				return fmt.Errorf("netlink: truncated error message")
			}
			code := int32(binary.LittleEndian.Uint32(buf[16:]))
			if code == 0 {
				return nil // ACK
			}
			return fmt.Errorf("netlink: kernel refused the request: %s", syscall.Errno(-code))
		}
		// Skip anything that is not our ACK (e.g. a multicast notification).
	}
}

// linkMessage builds an RTM_NEWLINK/RTM_DELLINK message with the given payload
// attributes and interface name.
func linkMessage(typ uint16, flags uint16, name string, extra func([]byte) []byte) []byte {
	ifi := ifInfomsg{Family: nlFamilies}
	body := make([]byte, 0, 128)
	body = binary.LittleEndian.AppendUint16(body, ifi.Type)
	body = binary.LittleEndian.AppendUint16(body, 0) // padding
	body = binary.LittleEndian.AppendUint32(body, uint32(ifi.Index))
	body = binary.LittleEndian.AppendUint32(body, ifi.Flags)
	body = binary.LittleEndian.AppendUint32(body, ifi.Change)

	body = attrString(body, iflaIfName, name)
	if extra != nil {
		body = extra(body)
	}

	return nlMessage(typ, flags, body)
}

// nlMessage frames a payload in an rtnetlink header.
func nlMessage(typ, flags uint16, body []byte) []byte {
	total := 16 + len(body)
	out := make([]byte, 0, total)
	out = binary.LittleEndian.AppendUint32(out, uint32(total))
	out = binary.LittleEndian.AppendUint16(out, typ)
	out = binary.LittleEndian.AppendUint16(out, flags)
	out = binary.LittleEndian.AppendUint16(out, 1) // serial
	out = binary.LittleEndian.AppendUint16(out, 0) // pid, 0 = kernel
	out = append(out, body...)
	return out
}

// ---------------------------------------------------------------------------
// veth
// ---------------------------------------------------------------------------

// Handle tracks the host-side objects created for one container so they can be
// removed again. Without this, every failed or stopped container leaves a veth
// pair and possibly a bridge behind on the host.
type Handle struct {
	// HostPeer is the interface that stays in the host namespace.
	HostPeer string
	// Bridge is the host bridge, empty if none was requested.
	Bridge string
	// bridgeCreated records whether we are the ones who made the bridge, so
	// teardown does not delete a bridge somebody else owns.
	bridgeCreated bool
}

// Attach creates a veth pair, moves one end into the network namespace of pid,
// and attaches the host end to a bridge.
func Attach(pid int, bridge string) (*Handle, error) {
	nsFile, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return nil, fmt.Errorf("netns: open namespace of pid %d: %w", pid, err)
	}
	defer nsFile.Close()

	hostEnd := fmt.Sprintf("veth%dh", pid)
	peerEnd := fmt.Sprintf("veth%dc", pid)

	if err := ensureBridge(bridge); err != nil {
		return nil, err
	}

	c, err := dialNetlink()
	if err != nil {
		return nil, err
	}
	defer c.Close()

	if err := createVeth(c, hostEnd, peerEnd, int(nsFile.Fd())); err != nil {
		return nil, err
	}

	h := &Handle{HostPeer: hostEnd, Bridge: bridge}
	if bridge != "" {
		if err := setMaster(c, hostEnd, bridge); err != nil {
			h.Teardown()
			return nil, err
		}
	}
	if err := linkUp(hostEnd); err != nil {
		h.Teardown()
		return nil, err
	}
	return h, nil
}

// createVeth issues an RTM_NEWLINK that creates a veth pair whose peer is
// placed directly into the namespace referenced by nsFd.
func createVeth(c *netlinkConn, host, peer string, nsFd int) error {
	msg := linkMessage(msgNewLink, nlFlagsRequest|nlFlagsAck, host, func(b []byte) []byte {
		var liStart int
		b, liStart = attrNested(b, iflaLinkInfo)
		b = attrString(b, iflaInfoKind, "veth")

		var dataStart int
		b, dataStart = attrNested(b, iflaInfoData)

		var peerStart int
		b, peerStart = attrNested(b, vethInfoPeer)
		// The peer carries its own ifinfomsg header.
		b = binary.LittleEndian.AppendUint16(b, 0) // family 0 (AF_UNSPEC)
		b = binary.LittleEndian.AppendUint16(b, 0) // type
		b = binary.LittleEndian.AppendUint32(b, 0) // index
		b = binary.LittleEndian.AppendUint32(b, 0) // flags
		b = binary.LittleEndian.AppendUint32(b, 0) // change
		b = attrString(b, iflaIfName, peer)
		// Point the kernel at the target namespace so it does the move itself.
		b = attrU32(b, iflaNetNsFd, uint32(nsFd))
		b = closeNested(b, peerStart)

		b = closeNested(b, dataStart)
		b = closeNested(b, liStart)
		return b
	})
	return c.request(msg)
}

// setMaster enslaves an interface to a bridge.
func setMaster(c *netlinkConn, iface, bridge string) error {
	idx, err := ifIndex(bridge)
	if err != nil {
		return err
	}
	// IFLA_MASTER is attribute 10.
	msg := linkMessage(msgNewLink, nlFlagsRequest|nlFlagsAck, iface, func(b []byte) []byte {
		return attrU32(b, 10, uint32(idx))
	})
	return c.request(msg)
}

// ensureBridge creates the bridge if it does not already exist.
//
// A shared bridge is left alone on purpose: several containers normally share
// one, and deleting it on the last exit would take everyone's networking with
// it.
func ensureBridge(name string) error {
	if name == "" {
		return nil
	}
	if _, err := ifIndex(name); err == nil {
		return nil
	}
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer c.Close()

	msg := linkMessage(msgNewLink, nlFlagsRequest|nlFlagsAck, name, func(b []byte) []byte {
		var start int
		b, start = attrNested(b, iflaLinkInfo)
		b = attrString(b, iflaInfoKind, "bridge")
		return closeNested(b, start)
	})
	if err := c.request(msg); err != nil {
		return fmt.Errorf("netns: create bridge %s: %w", name, err)
	}
	return linkUp(name)
}

// Teardown removes the host-side objects this handle created.
func (h *Handle) Teardown() error {
	if h == nil || h.HostPeer == "" {
		return nil
	}
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer c.Close()

	// Deleting one end of a veth pair deletes both, and any interface enslaved
	// to a bridge, so the container's end disappears with it.
	err = c.request(linkMessage(msgDelLink, nlFlagsRequest|nlFlagsAck, h.HostPeer, nil))
	h.HostPeer = ""
	return err
}

// ---------------------------------------------------------------------------
// ioctl-based link control
//
// Bringing an interface up is far simpler through the legacy ioctl than through
// netlink, and the kernel has kept it working for twenty years.
// ---------------------------------------------------------------------------

// ifreq is the legacy interface request structure.
type ifreq struct {
	Name [16]byte
	Data uintptr
}

// SIOCGIFFLAGS / SIOCSIFFLAGS from include/uapi/linux/sockios.h.
const (
	siocGIFFlags = 0x8913
	siocSIFFlags = 0x8914
)

// linkUp sets IFF_UP on an interface.
func linkUp(name string) error { return setFlags(name, iffUp, iffUp) }

func setFlags(name string, flags, change uint32) error {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("netns: socket: %w", err)
	}
	defer syscall.Close(fd)

	var req ifreq
	if len(name) >= len(req.Name) {
		return fmt.Errorf("netns: interface name %q too long", name)
	}
	copy(req.Name[:], name)

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(siocGIFFlags), uintptr(unsafe.Pointer(&req))); errno != 0 {
		return fmt.Errorf("netns: get flags for %s: %w", name, errno)
	}
	// req.Data is a uintptr because that is the width ifreq's union member is
	// declared with, but it carries a 32-bit flags word.
	req.Data = (uintptr(uint32(req.Data)) &^ uintptr(change)) | uintptr(flags)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(siocSIFFlags), uintptr(unsafe.Pointer(&req))); errno != 0 {
		return fmt.Errorf("netns: set flags for %s: %w", name, errno)
	}
	return nil
}

// ifIndex resolves an interface name to its kernel index.
func ifIndex(name string) (int, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer syscall.Close(fd)

	var req ifreq
	copy(req.Name[:], name)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd),
		uintptr(siocGIFFlags), uintptr(unsafe.Pointer(&req))); errno != 0 {
		return 0, fmt.Errorf("netns: interface %q: %w", name, errno)
	}
	// The ifindex shares a struct slot with the flags word.
	return int(int32(uint32(req.Data))), nil
}

// EnableLoopback brings up lo inside the current network namespace.
//
// A fresh network namespace has lo present but DOWN. Leaving it down breaks
// essentially every networked program: a client connecting to 127.0.0.1 fails
// with ECONNREFUSED, and DNS resolution against a local resolver hangs.
func EnableLoopback() error {
	return linkUp("lo")
}

// AssignAddress adds an IPv4 address to an interface in the current namespace.
func AssignAddress(iface string, ip net.IP, prefixLen int) error {
	c, err := dialNetlink()
	if err != nil {
		return err
	}
	defer c.Close()

	v4 := ip.To4()
	if v4 == nil {
		return fmt.Errorf("netns: only IPv4 addresses are supported, got %s", ip)
	}

	rt := rtmsg{Family: syscall.AF_INET, Scope: 0, Protocol: syscall.RTPROT_STATIC, Type: syscall.RTN_UNICAST}
	body := make([]byte, 0, 64)
	body = append(body, rt.Family, rt.DstLen, rt.SrcLen, rt.Tos, rt.Table, rt.Protocol, rt.Scope, rt.Type)
	body = binary.LittleEndian.AppendUint32(body, rt.Flags)
	body = attr(body, ifaLocal, v4)
	body = attr(body, ifaAddress, v4)
	// Broadcast is mandatory for IPv4; the kernel will not infer one.
	body = attr(body, ifaBroadcast, []byte{255, 255, 255, 255})

	return c.request(nlMessage(msgNewAddr, nlFlagsRequest|nlFlagsAck, body))
}
