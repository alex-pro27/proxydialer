package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"golang.org/x/net/proxy"
)

const (
	socks5CmdBind         = 0x02
	socks5CmdUDPAssociate = 0x03
)

// udpTarget — адрес назначения/источника UDP-дейтаграммы.
type udpTarget struct {
	host string
	port int
}

func (t udpTarget) String() string { return net.JoinHostPort(t.host, strconv.Itoa(t.port)) }

// udpResponse — ответ upstream, который нужно вернуть клиенту.
type udpResponse struct {
	target udpTarget
	data   []byte
}

// udpAssoc — абстракция upstream-канала для UDP-релея.
type udpAssoc interface {
	WriteTo(p []byte, t udpTarget) error
	ReadFrom(p []byte) (int, *udpTarget, error)
	Close() error
}

// udpFactory создаёт новую ассоциацию с upstream.
type udpFactory func() (udpAssoc, error)

// parseSocks5Addr разбирает ATYP ADDR PORT из буфера и возвращает число
// прочитанных байт.
func parseSocks5Addr(b []byte) (host string, port, n int, err error) {
	if len(b) < 1 {
		return "", 0, 0, errors.New("socks5: empty address")
	}
	off := 1
	switch b[0] {
	case socks5AtypIPv4:
		if len(b) < off+net.IPv4len {
			return "", 0, 0, errors.New("socks5: short ipv4 address")
		}
		host = net.IP(b[off : off+net.IPv4len]).String()
		off += net.IPv4len
	case socks5AtypIPv6:
		if len(b) < off+net.IPv6len {
			return "", 0, 0, errors.New("socks5: short ipv6 address")
		}
		host = net.IP(b[off : off+net.IPv6len]).String()
		off += net.IPv6len
	case socks5AtypDomain:
		if len(b) < off+1 {
			return "", 0, 0, errors.New("socks5: short domain length")
		}
		l := int(b[off])
		off++
		if l == 0 || len(b) < off+l {
			return "", 0, 0, errors.New("socks5: short domain address")
		}
		host = string(b[off : off+l])
		off += l
	default:
		return "", 0, 0, fmt.Errorf("socks5: unsupported address type %d", b[0])
	}
	if len(b) < off+2 {
		return "", 0, 0, errors.New("socks5: short port")
	}
	port = int(b[off])<<8 | int(b[off+1])
	off += 2
	return host, port, off, nil
}

// readSocks5Addr читает ADDR PORT из io.Reader для заданного ATYP (для разбора
// ответов upstream, где ATYP уже прочитан отдельно).
func readSocks5Addr(r io.Reader, atyp byte) (host string, port int, err error) {
	switch atyp {
	case socks5AtypIPv4:
		b := make([]byte, net.IPv4len)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case socks5AtypIPv6:
		b := make([]byte, net.IPv6len)
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = net.IP(b).String()
	case socks5AtypDomain:
		var l [1]byte
		if _, err = io.ReadFull(r, l[:]); err != nil {
			return
		}
		if l[0] == 0 {
			err = errors.New("socks5: empty domain")
			return
		}
		b := make([]byte, int(l[0]))
		if _, err = io.ReadFull(r, b); err != nil {
			return
		}
		host = string(b)
	default:
		err = fmt.Errorf("socks5: unsupported address type %d", atyp)
		return
	}
	var p [2]byte
	if _, err = io.ReadFull(r, p[:]); err != nil {
		return
	}
	port = int(p[0])<<8 | int(p[1])
	return
}

// parseUDPDatagram разбирает SOCKS5 UDP-дейтаграмму: RSV(2) FRAG(1) ATYP ADDR PORT DATA.
func parseUDPDatagram(b []byte) (udpTarget, []byte, error) {
	if len(b) < 4 {
		return udpTarget{}, nil, errors.New("socks5: short udp datagram")
	}
	if b[0] != 0 || b[1] != 0 {
		return udpTarget{}, nil, errors.New("socks5: invalid reserved field")
	}
	if b[2] != 0 {
		return udpTarget{}, nil, errors.New("socks5: udp fragmentation not supported")
	}
	host, port, n, err := parseSocks5Addr(b[3:])
	if err != nil {
		return udpTarget{}, nil, err
	}
	return udpTarget{host: host, port: port}, b[3+n:], nil
}

// buildUDPDatagram собирает SOCKS5 UDP-дейтаграмму: RSV(2) FRAG(1) ATYP ADDR PORT DATA.
func buildUDPDatagram(t udpTarget, data []byte) []byte {
	buf := make([]byte, 0, 4+len(t.host)+2+len(data))
	buf = append(buf, 0, 0, 0)
	buf = encodeUDPAddr(buf, t)
	buf = append(buf, data...)
	return buf
}

// encodeUDPAddr дописывает ATYP ADDR PORT в buf.
func encodeUDPAddr(buf []byte, t udpTarget) []byte {
	if ip := net.ParseIP(t.host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, socks5AtypIPv4)
			buf = append(buf, ip4...)
		} else {
			buf = append(buf, socks5AtypIPv6)
			buf = append(buf, ip.To16()...)
		}
	} else {
		buf = append(buf, socks5AtypDomain, byte(len(t.host)))
		buf = append(buf, t.host...)
	}
	buf = append(buf, byte(t.port>>8), byte(t.port&0xff))
	return buf
}

// directAssoc — прямой (без прокси) UDP-канал: по сокету на каждое семейство адресов.
type directAssoc struct {
	v4        *net.UDPConn
	v6        *net.UDPConn
	ch        chan udpResponse
	done      chan struct{}
	startOnce sync.Once
	closeOnce sync.Once
}

func newDirectAssoc() (udpAssoc, error) {
	v4, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	d := &directAssoc{v4: v4, ch: make(chan udpResponse, 32), done: make(chan struct{})}
	if v6, err := net.ListenUDP("udp6", nil); err == nil {
		d.v6 = v6
	}
	return d, nil
}

func (d *directAssoc) start() {
	d.startOnce.Do(func() {
		go d.readLoop(d.v4)
		if d.v6 != nil {
			go d.readLoop(d.v6)
		}
	})
}

func (d *directAssoc) readLoop(c *net.UDPConn) {
	buf := make([]byte, 64*1024)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-d.done:
				return
			default:
				d.Close()
				return
			}
		}
		data := make([]byte, n)
		copy(data, buf[:n])
		select {
		case d.ch <- udpResponse{target: udpTarget{host: src.IP.String(), port: src.Port}, data: data}:
		case <-d.done:
			return
		}
	}
}

func (d *directAssoc) WriteTo(p []byte, t udpTarget) error {
	addr, err := net.ResolveUDPAddr("udp", t.String())
	if err != nil {
		return err
	}
	if addr.IP.To4() != nil {
		if d.v4 == nil {
			return errors.New("no ipv4 socket")
		}
		_, err = d.v4.WriteToUDP(p, addr)
		return err
	}
	if d.v6 == nil {
		return errors.New("no ipv6 socket")
	}
	_, err = d.v6.WriteToUDP(p, addr)
	return err
}

func (d *directAssoc) ReadFrom(p []byte) (int, *udpTarget, error) {
	d.start()
	select {
	case <-d.done:
		return 0, nil, io.EOF
	case r, ok := <-d.ch:
		if !ok {
			return 0, nil, io.EOF
		}
		n := copy(p, r.data)
		return n, &r.target, nil
	}
}

func (d *directAssoc) Close() error {
	d.closeOnce.Do(func() {
		close(d.done)
		if d.v4 != nil {
			d.v4.Close()
		}
		if d.v6 != nil {
			d.v6.Close()
		}
	})
	return nil
}

// socks5Assoc — UDP-канал через upstream SOCKS5 (UDP ASSOCIATE).
type socks5Assoc struct {
	control   net.Conn
	relayAddr *net.UDPAddr
	conn      *net.UDPConn
}

// socks5Associate выполняет TCP-хендшейк и UDP ASSOCIATE к upstream-прокси,
// возвращает контрольное соединение и адрес UDP-релея.
func socks5Associate(addr string, auth *proxy.Auth) (net.Conn, *net.UDPAddr, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	fail := func(err error) (net.Conn, *net.UDPAddr, error) {
		conn.Close()
		return nil, nil, err
	}

	var methods []byte
	if auth != nil && (auth.User != "" || auth.Password != "") {
		methods = []byte{socks5MethodNoAuth, socks5MethodUserPass}
	} else {
		methods = []byte{socks5MethodNoAuth}
	}
	if _, err := conn.Write([]byte{socks5Version, byte(len(methods))}); err != nil {
		return fail(err)
	}
	if _, err := conn.Write(methods); err != nil {
		return fail(err)
	}

	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return fail(err)
	}
	if sel[0] != socks5Version {
		return fail(fmt.Errorf("socks5: bad version in method selection %d", sel[0]))
	}
	switch sel[1] {
	case socks5MethodUserPass:
		if auth == nil {
			return fail(errors.New("socks5: server requested auth, none provided"))
		}
		if len(auth.User) > 255 || len(auth.Password) > 255 {
			return fail(errors.New("socks5: credentials too long"))
		}
		buf := []byte{0x01, byte(len(auth.User))}
		buf = append(buf, auth.User...)
		buf = append(buf, byte(len(auth.Password)))
		buf = append(buf, auth.Password...)
		if _, err := conn.Write(buf); err != nil {
			return fail(err)
		}
		var ar [2]byte
		if _, err := io.ReadFull(conn, ar[:]); err != nil {
			return fail(err)
		}
		if ar[1] != 0x00 {
			return fail(errors.New("socks5: authentication failed"))
		}
	case socks5MethodNoAuth:
	default:
		return fail(fmt.Errorf("socks5: no acceptable auth method %d", sel[1]))
	}

	// UDP ASSOCIATE c нулевым адресом (0.0.0.0:0).
	if _, err := conn.Write([]byte{socks5Version, socks5CmdUDPAssociate, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return fail(err)
	}
	var rep [4]byte
	if _, err := io.ReadFull(conn, rep[:]); err != nil {
		return fail(err)
	}
	if rep[0] != socks5Version || rep[1] != socks5RepSuccess {
		return fail(fmt.Errorf("socks5: udp associate failed (rep=%d)", rep[1]))
	}
	host, port, err := readSocks5Addr(conn, rep[3])
	if err != nil {
		return fail(err)
	}
	relayAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return fail(err)
	}
	return conn, relayAddr, nil
}

func newSocks5Assoc(addr string, auth *proxy.Auth) (udpAssoc, error) {
	control, relayAddr, err := socks5Associate(addr, auth)
	if err != nil {
		return nil, err
	}

	var conn *net.UDPConn
	if relayAddr.IP.To4() != nil {
		conn, err = net.ListenUDP("udp4", nil)
	} else {
		conn, err = net.ListenUDP("udp6", nil)
	}
	if err != nil {
		control.Close()
		return nil, err
	}

	a := &socks5Assoc{control: control, relayAddr: relayAddr, conn: conn}

	// Держим контрольное соединение открытым; при его закрытии рвём UDP-релей.
	go func() {
		buf := make([]byte, 512)
		for {
			if _, err := control.Read(buf); err != nil {
				a.conn.Close()
				return
			}
		}
	}()

	return a, nil
}

func (s *socks5Assoc) WriteTo(p []byte, t udpTarget) error {
	buf := buildUDPDatagram(t, p)
	_, err := s.conn.WriteToUDP(buf, s.relayAddr)
	return err
}

func (s *socks5Assoc) ReadFrom(p []byte) (int, *udpTarget, error) {
	buf := make([]byte, 64*1024)
	n, _, err := s.conn.ReadFromUDP(buf)
	if err != nil {
		return 0, nil, err
	}
	tgt, data, err := parseUDPDatagram(buf[:n])
	if err != nil {
		return 0, nil, err
	}
	m := copy(p, data)
	return m, &tgt, nil
}

func (s *socks5Assoc) Close() error {
	s.conn.Close()
	s.control.Close()
	return nil
}

// writeUDPAssociateReply отправляет клиенту успешный ответ UDP ASSOCIATE с BND-адресом.
func writeUDPAssociateReply(conn net.Conn, relayAddr *net.UDPAddr) error {
	var buf []byte
	buf = append(buf, socks5Version, socks5RepSuccess, 0x00)
	if ip4 := relayAddr.IP.To4(); ip4 != nil {
		buf = append(buf, socks5AtypIPv4)
		buf = append(buf, ip4...)
	} else {
		buf = append(buf, socks5AtypIPv6)
		buf = append(buf, relayAddr.IP.To16()...)
	}
	buf = append(buf, byte(relayAddr.Port>>8), byte(relayAddr.Port&0xff))
	_, err := conn.Write(buf)
	return err
}

// serveUDPAssociate обслуживает один UDP-релей: читает дейтаграммы от клиента,
// маршрутизирует их через upstream и возвращает ответы обратно.
func serveUDPAssociate(control net.Conn, relay *net.UDPConn, resolve func(host string) (upstream, string), label string) {
	var (
		mu         sync.Mutex
		assocs     = make(map[string]udpAssoc)
		clientAddr atomic.Value // *net.UDPAddr
	)

	done := make(chan struct{})
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			close(done)
			relay.Close()
			control.Close()
			mu.Lock()
			for _, a := range assocs {
				a.Close()
			}
			mu.Unlock()
		})
	}
	defer shutdown()

	// Следим за TCP-контрольным соединением: закрытие = разрыв релея.
	go func() {
		buf := make([]byte, 1)
		for {
			if _, err := control.Read(buf); err != nil {
				shutdown()
				return
			}
		}
	}()

	respCh := make(chan udpResponse, 32)

	// Пишем ответы обратно клиенту.
	go func() {
		for {
			select {
			case <-done:
				return
			case r := <-respCh:
				if ca, ok := clientAddr.Load().(*net.UDPAddr); ok && ca != nil {
					relay.WriteToUDP(buildUDPDatagram(r.target, r.data), ca)
				}
			}
		}
	}()

	getAssoc := func(key string, f udpFactory) udpAssoc {
		mu.Lock()
		if a, ok := assocs[key]; ok {
			mu.Unlock()
			return a
		}
		if f == nil {
			mu.Unlock()
			return nil
		}
		a, err := f()
		if err != nil {
			mu.Unlock()
			log.Printf("[%s:udp] failed to associate upstream %q: %v", label, key, err)
			return nil
		}
		assocs[key] = a
		mu.Unlock()

		go func() {
			buf := make([]byte, 64*1024)
			for {
				n, tgt, err := a.ReadFrom(buf)
				if err != nil {
					return
				}
				data := make([]byte, n)
				copy(data, buf[:n])
				select {
				case respCh <- udpResponse{target: *tgt, data: data}:
				case <-done:
					return
				}
			}
		}()
		return a
	}

	reqBuf := make([]byte, 64*1024)
	for {
		n, src, err := relay.ReadFromUDP(reqBuf)
		if err != nil {
			return
		}
		if clientAddr.Load() == nil {
			clientAddr.Store(src)
		}

		tgt, payload, err := parseUDPDatagram(reqBuf[:n])
		if err != nil {
			continue
		}

		up, reason := resolve(tgt.host)
		via := "proxy"
		if up.isDirect() {
			via = "direct"
		}
		log.Printf("[%s:udp] %s → %s → %s (%s)", label, src, tgt.String(), via, reason)

		if up.udp == nil {
			log.Printf("[%s:udp] drop %s: upstream does not support UDP (http)", label, tgt.String())
			continue
		}

		a := getAssoc(up.key, up.udp)
		if a == nil {
			continue
		}
		if err := a.WriteTo(payload, tgt); err != nil {
			log.Printf("[%s:udp] write to %s failed: %v", label, tgt.String(), err)
		}
	}
}
