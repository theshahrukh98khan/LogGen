// Package sink is a minimal syslog receiver. It exists so the send pipeline can
// be verified locally, before pointing LogGen at a real Wazuh manager.
package sink

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
)

// Run listens on addr for both UDP and TCP syslog and prints what arrives.
// It blocks until one of the listeners fails.
func Run(addr string) error {
	errs := make(chan error, 2)
	var wg sync.WaitGroup

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", addr, err)
	}
	defer pc.Close()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen tcp %s: %w", addr, err)
	}
	defer ln.Close()

	log.Printf("syslog sink listening on udp/%s and tcp/%s", addr, addr)

	wg.Add(2)
	go func() {
		defer wg.Done()
		errs <- serveUDP(pc)
	}()
	go func() {
		defer wg.Done()
		errs <- serveTCP(ln)
	}()

	return <-errs
}

func serveUDP(pc net.PacketConn) error {
	// 64 KiB is the largest a single UDP datagram can be.
	buf := make([]byte, 65535)
	for {
		n, remote, err := pc.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("udp read: %w", err)
		}
		report("udp", remote.String(), string(buf[:n]))
	}
}

func serveTCP(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("tcp accept: %w", err)
		}
		go func(c net.Conn) {
			defer c.Close()
			sc := bufio.NewScanner(c)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for sc.Scan() {
				report("tcp", c.RemoteAddr().String(), sc.Text())
			}
		}(conn)
	}
}

func report(proto, remote, msg string) {
	msg = strings.TrimRight(msg, "\r\n")
	if msg == "" {
		return
	}
	fmt.Printf("[%s %s] %s\n", proto, remote, msg)
}
