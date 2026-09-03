package main

import (
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestBuildAndParseUDPDatagram(t *testing.T) {
	tests := []udpTarget{
		{host: "example.com", port: 443},
		{host: "1.2.3.4", port: 53},
		{host: "2001:67c:4e8::1", port: 5353},
	}
	payload := []byte("hello-udp")
	for _, target := range tests {
		d := buildUDPDatagram(target, payload)
		got, data, err := parseUDPDatagram(d)
		if err != nil {
			t.Fatalf("parseUDPDatagram(%v): %v", target, err)
		}
		if got.host != target.host || got.port != target.port {
			t.Errorf("target = %v, want %v", got, target)
		}
		if string(data) != string(payload) {
			t.Errorf("payload = %q, want %q", data, payload)
		}
	}
}

func TestParseUDPDatagramRejectsFragment(t *testing.T) {
	d := []byte{0x00, 0x00, 0x01, socks5AtypIPv4, 1, 2, 3, 4, 0, 53, 'x'}
	if _, _, err := parseUDPDatagram(d); err == nil {
		t.Error("expected error for fragmented datagram")
	}
}

// readTestSocks5Reply читает ответ SOCKS5 (VER REP RSV ATYP ADDR PORT) из потока.
func readTestSocks5Reply(r io.Reader) (rep byte, addr string, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	rep = hdr[1]
	host, port, err := readSocks5Addr(r, hdr[3])
	if err != nil {
		return
	}
	addr = net.JoinHostPort(host, strconv.Itoa(port))
	return
}

// udpEchoServer поднимает UDP-эхо-сервер на 127.0.0.1.
func udpEchoServer(t *testing.T) net.Addr {
	t.Helper()
	echo, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { echo.Close() })
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := echo.ReadFromUDP(buf)
			if err != nil {
				return
			}
			echo.WriteToUDP(buf[:n], addr)
		}
	}()
	return echo.LocalAddr()
}

func TestServeSOCKS5UDPAssociateDirect(t *testing.T) {
	echoAddr := udpEchoServer(t)

	client, server := net.Pipe()
	defer client.Close()

	go serveSOCKS5(server, nil, "test", func(host string) (upstream, string) {
		return directUpstream, "default"
	})

	// Greeting: no-auth
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	gr := make([]byte, 2)
	if _, err := io.ReadFull(client, gr); err != nil {
		t.Fatal(err)
	}
	if gr[0] != 0x05 || gr[1] != 0x00 {
		t.Fatalf("unexpected method selection %v", gr)
	}

	// UDP ASSOCIATE
	if _, err := client.Write([]byte{0x05, socks5CmdUDPAssociate, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rep, relayStr, err := readTestSocks5Reply(client)
	if err != nil {
		t.Fatal(err)
	}
	if rep != socks5RepSuccess {
		t.Fatalf("UDP ASSOCIATE failed: rep=%d", rep)
	}
	relayAddr, err := net.ResolveUDPAddr("udp", relayStr)
	if err != nil {
		t.Fatal(err)
	}

	cli, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	echoHost, echoPortStr, err := net.SplitHostPort(echoAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	echoPort, err := strconv.Atoi(echoPortStr)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello-udp")
	tgt := udpTarget{host: echoHost, port: echoPort}
	if _, err := cli.WriteToUDP(buildUDPDatagram(tgt, payload), relayAddr); err != nil {
		t.Fatal(err)
	}

	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64*1024)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	_, data, err := parseUDPDatagram(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(payload) {
		t.Fatalf("relay = %q, want %q", data, payload)
	}
}

// handleMockSocks5Upstream обслуживает upstream-SOCKS5: поддержка UDP ASSOCIATE с эхо.
func handleMockSocks5Upstream(c net.Conn) {
	defer c.Close()

	var g [2]byte
	if _, err := io.ReadFull(c, g[:]); err != nil {
		return
	}
	if g[0] != socks5Version {
		return
	}
	methods := make([]byte, int(g[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if _, err := c.Write([]byte{socks5Version, socks5MethodNoAuth}); err != nil {
		return
	}

	var req [4]byte
	if _, err := io.ReadFull(c, req[:]); err != nil {
		return
	}
	if req[0] != socks5Version {
		return
	}
	if _, _, err := readSocks5Addr(c, req[3]); err != nil {
		return
	}

	if req[1] != socks5CmdUDPAssociate {
		c.Write([]byte{socks5Version, socks5RepCommandNotSupported, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return
	}
	defer relay.Close()

	rAddr := relay.LocalAddr().(*net.UDPAddr)
	var rep []byte
	rep = append(rep, socks5Version, socks5RepSuccess, 0x00, socks5AtypIPv4)
	rep = append(rep, rAddr.IP.To4()...)
	rep = append(rep, byte(rAddr.Port>>8), byte(rAddr.Port&0xff))
	if _, err := c.Write(rep); err != nil {
		return
	}

	buf := make([]byte, 64*1024)
	for {
		n, addr, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		relay.WriteToUDP(buf[:n], addr)
	}
}

func TestServeSOCKS5UDPAssociateViaSocks5(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()
	go func() {
		for {
			c, err := upLn.Accept()
			if err != nil {
				return
			}
			go handleMockSocks5Upstream(c)
		}
	}()

	up, err := buildDialer(ProxyEntry{Proxy: upLn.Addr().String(), Protocol: SOCKS5})
	if err != nil {
		t.Fatal(err)
	}

	client, server := net.Pipe()
	defer client.Close()

	go serveSOCKS5(server, nil, "test", func(host string) (upstream, string) {
		return up, "default"
	})

	// Greeting
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	gr := make([]byte, 2)
	if _, err := io.ReadFull(client, gr); err != nil {
		t.Fatal(err)
	}

	// UDP ASSOCIATE
	if _, err := client.Write([]byte{0x05, socks5CmdUDPAssociate, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	rep, relayStr, err := readTestSocks5Reply(client)
	if err != nil {
		t.Fatal(err)
	}
	if rep != socks5RepSuccess {
		t.Fatalf("UDP ASSOCIATE failed: rep=%d", rep)
	}
	relayAddr, err := net.ResolveUDPAddr("udp", relayStr)
	if err != nil {
		t.Fatal(err)
	}

	cli, err := net.ListenUDP("udp4", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	tgt := udpTarget{host: "8.8.8.8", port: 53}
	payload := []byte("dns-query")
	if _, err := cli.WriteToUDP(buildUDPDatagram(tgt, payload), relayAddr); err != nil {
		t.Fatal(err)
	}

	cli.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64*1024)
	n, _, err := cli.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	gotTgt, data, err := parseUDPDatagram(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(payload) {
		t.Fatalf("relay = %q, want %q", data, payload)
	}
	if gotTgt.host != "8.8.8.8" || gotTgt.port != 53 {
		t.Fatalf("target = %v, want 8.8.8.8:53", gotTgt)
	}
}
