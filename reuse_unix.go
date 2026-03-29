//go:build !windows

package main

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// reuseListenUDP creates a UDP socket bound to the given port with
// SO_REUSEADDR and SO_REUSEPORT set, allowing it to share the port
// with the main QUIC socket.
func reuseListenUDP(port int) (*net.UDPConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}

	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("SO_REUSEADDR: %w", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("SO_REUSEPORT: %w", err)
	}

	sa := &syscall.SockaddrInet4{Port: port}
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind: %w", err)
	}

	file := os.NewFile(uintptr(fd), fmt.Sprintf("udp-punch:%d", port))
	defer file.Close()

	fc, err := net.FilePacketConn(file)
	if err != nil {
		return nil, fmt.Errorf("FilePacketConn: %w", err)
	}

	udpConn, ok := fc.(*net.UDPConn)
	if !ok {
		fc.Close()
		return nil, fmt.Errorf("not a UDPConn")
	}
	return udpConn, nil
}
