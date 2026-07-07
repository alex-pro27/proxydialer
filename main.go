package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

type Protocol string

const (
	SOCKS5 Protocol = "socks5"
	HTTP   Protocol = "http"
)

const defaultConfigFileName = "config.yaml"

// AuthConfig описывает вложенную секцию авторизации.
type AuthConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

// ProxyEntry описывает одну запись прокси в конфиге.
type ProxyEntry struct {
	Dialer   string     `yaml:"dialer"`           // локальный адрес слушателя, например 127.0.0.1:7492
	Proxy    string     `yaml:"proxy"`            // адрес удалённого прокси, например 85.193.81.230:1818
	Protocol Protocol   `yaml:"protocol"`         // "socks5" или "http"
	Username string     `yaml:"username,omitempty"` // плоский формат (старый)
	Password string     `yaml:"password,omitempty"` // плоский формат (старый)
	Auth     *AuthConfig `yaml:"auth,omitempty"`    // вложенный формат (новый)
	Use      bool       `yaml:"use"`              // включить/выключить
	Exclude  []string   `yaml:"exclude"`          // домены, которые обходят прокси напрямую
	Only     []string   `yaml:"only"`             // домены, которые идут ТОЛЬКО через прокси; всё остальное — напрямую
	Name     string     `yaml:"name,omitempty"`   // имя прокси для ссылок из routes
}

func (e ProxyEntry) GetUsername() string {
	if e.Auth != nil && e.Auth.Username != "" {
		return e.Auth.Username
	}
	return e.Username
}

func (e ProxyEntry) GetPassword() string {
	if e.Auth != nil && e.Auth.Password != "" {
		return e.Auth.Password
	}
	return e.Password
}

// configHash возвращает строку-отпечаток конфигурации для обнаружения изменений.
func (e *ProxyEntry) configHash() string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%v|%v|%v|%s",
		e.Dialer, e.Proxy, e.Protocol, e.GetUsername(), e.GetPassword(), e.Use, e.Exclude, e.Only, e.Name)
}

// RouteRule задаёт приоритет именованного прокси в правилах маршрутизации.
type RouteRule struct {
	Priority int `yaml:"priority"`
	Pririty  int `yaml:"pririty"` // поддержка опечатки в конфиге
}

func (r RouteRule) GetPriority() int {
	if r.Priority != 0 {
		return r.Priority
	}
	return r.Pririty
}

// RouteEntry описывает маршрут — слушатель, который объединяет несколько прокси по приоритетам.
type RouteEntry struct {
	Dialer  string               `yaml:"proxy"`        // адрес слушателя маршрута
	Use     bool                 `yaml:"use"`           // включить/выключить
	Exclude []string             `yaml:"exclude"`       // домены-исключения на уровне маршрута
	Only    []string             `yaml:"only"`          // домены, идущие только через маршрут
	Auth    *AuthConfig          `yaml:"auth,omitempty"` // опциональная HTTP-авторизация на слушателе
	Rules   map[string]RouteRule `yaml:"rules"`         // имя прокси → приоритет
}

// configHash возвращает строку-отпечаток маршрута для обнаружения изменений.
func (r *RouteEntry) configHash() string {
	names := make([]string, 0, len(r.Rules))
	for name := range r.Rules {
		names = append(names, name)
	}
	sort.Strings(names)
	var rulesParts []string
	for _, name := range names {
		rule := r.Rules[name]
		rulesParts = append(rulesParts, fmt.Sprintf("%s:%d", name, rule.GetPriority()))
	}
	authPart := ""
	if r.Auth != nil {
		authPart = fmt.Sprintf("%s:%s", r.Auth.Username, r.Auth.Password)
	}
	return fmt.Sprintf("%s|%v|%v|%v|%s|%s",
		r.Dialer, r.Use, r.Exclude, r.Only, authPart, strings.Join(rulesParts, ","))
}

// Config — корневой тип конфигурационного файла.
type Config struct {
	Version string       `yaml:"version"`
	Routes  []RouteEntry `yaml:"routes"`
	Proxies []ProxyEntry `yaml:"proxies"`
}

// NamedProxy связывает запись прокси с собранным dialer-ом для использования в маршрутах.
type NamedProxy struct {
	Entry  ProxyEntry
	Dialer proxy.Dialer
}

type bufferedConn struct {
	net.Conn
	reader io.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

type httpConnectDialer struct {
	address    string
	authHeader string
	forward    proxy.Dialer
}

func (d *httpConnectDialer) Dial(network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("http proxy only supports tcp, got %q", network)
	}

	forward := d.forward
	if forward == nil {
		forward = proxy.Direct
	}

	conn, err := forward.Dial("tcp", d.address)
	if err != nil {
		return nil, err
	}

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr); err != nil {
		conn.Close()
		return nil, err
	}
	if d.authHeader != "" {
		if _, err := fmt.Fprintf(conn, "Proxy-Authorization: %s\r\n", d.authHeader); err != nil {
			conn.Close()
			return nil, err
		}
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		conn.Close()
		return nil, err
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		resp.Body.Close()
		conn.Close()
		msg := resp.Status
		if bodyText := strings.TrimSpace(string(body)); bodyText != "" {
			msg += ": " + bodyText
		}
		return nil, fmt.Errorf("http proxy connect failed: %s", msg)
	}

	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, reader: br}, nil
	}
	return conn, nil
}

func normalizeProtocol(protocol Protocol) Protocol {
	return Protocol(strings.ToLower(strings.TrimSpace(string(protocol))))
}

func proxyScheme(protocol Protocol) string {
	return string(normalizeProtocol(protocol))
}

// matchDomain проверяет, совпадает ли host с доменом.
// Поддерживает:
//   - точное совпадение:       "openai.com"  → openai.com
//   - поддомены:               "openai.com"  → api.openai.com, chat.openai.com
//   - явный wildcard-паттерн:  "*.openai.com" → openai.com, api.openai.com, chat.openai.com
func matchDomain(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))

	if strings.HasPrefix(domain, "*.") {
		suffix := domain[1:] // ".openai.com"
		base := domain[2:]   // "openai.com"
		return host == base || strings.HasSuffix(host, suffix)
	}

	return host == domain || strings.HasSuffix(host, "."+domain)
}

// shouldUseProxy определяет, должен ли запрос к host идти через прокси.
// Возвращает bool и строку-причину для логирования.
//
//   - Если задан only: трафик через прокси идёт только для перечисленных доменов.
//   - Если задан exclude: перечисленные домены обходят прокси.
//   - Если заданы оба: домен должен быть в only И не быть в exclude.
func shouldUseProxy(host string, entry ProxyEntry) (use bool, reason string) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if len(entry.Only) > 0 {
		for _, d := range entry.Only {
			if matchDomain(host, d) {
				for _, ex := range entry.Exclude {
					if matchDomain(host, ex) {
						return false, "only+exclude:" + ex
					}
				}
				return true, "only:" + d
			}
		}
		return false, "not-in-only"
	}

	for _, d := range entry.Exclude {
		if matchDomain(host, d) {
			return false, "exclude:" + d
		}
	}

	return true, "default"
}

func getConfigFile() string {
	if configFile, ok := os.LookupEnv("PROXY_DEALER_CONFIG_FILE"); ok {
		return configFile
	}
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal("cannot determine working directory:", err)
	}
	return filepath.Join(cwd, defaultConfigFileName)
}

func parseConfig(configFile string) (Config, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return Config{}, fmt.Errorf("cannot read config: %w", err)
	}
	var conf Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		return Config{}, fmt.Errorf("cannot parse config: %w", err)
	}
	return conf, nil
}

// ActiveConfig содержит активные прокси и маршруты после фильтрации.
type ActiveConfig struct {
	Proxies []ProxyEntry
	Routes  []RouteEntry
}

func getActiveConfig(configFile string) (ActiveConfig, error) {
	conf, err := parseConfig(configFile)
	if err != nil {
		return ActiveConfig{}, err
	}
	var proxies []ProxyEntry
	for _, p := range conf.Proxies {
		if !p.Use {
			continue
		}
		p.Protocol = normalizeProtocol(p.Protocol)
		switch p.Protocol {
		case SOCKS5, HTTP:
		default:
			log.Printf("skip proxy %s: protocol %q not supported (supported: socks5, http)", p.Proxy, p.Protocol)
			continue
		}
		proxies = append(proxies, p)
	}
	var routes []RouteEntry
	for _, r := range conf.Routes {
		if !r.Use {
			continue
		}
		routes = append(routes, r)
	}
	return ActiveConfig{Proxies: proxies, Routes: routes}, nil
}

// transfer копирует данные между двумя соединениями и закрывает оба.
func transfer(dst io.WriteCloser, src io.ReadCloser) {
	defer func() {
		if dst != nil {
			dst.Close()
		}
		if src != nil {
			src.Close()
		}
	}()
	if dst != nil && src != nil {
		io.Copy(dst, src)
	}
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

// dialerFor возвращает нужный dialer в зависимости от правил фильтрации.
func dialerFor(host string, proxyD proxy.Dialer, entry ProxyEntry) (proxy.Dialer, string) {
	if use, reason := shouldUseProxy(host, entry); use {
		return proxyD, reason
	} else {
		return proxy.Direct, reason
	}
}

// routeRequest выбирает прокси для домена согласно приоритетам маршрута.
// Алгоритм:
//  1. Пре-фильтр маршрута (собственные Only/Exclude)
//  2. Поиск only-совпадений среди прокси: домен в Only прокси → приоритет only-совпадений выше
//  3. Если only-совпадений нет — fallback на прокси, которые не исключают домен
//  4. Ни один прокси не совпал → Direct
func routeRequest(host string, route RouteEntry, proxies map[string]NamedProxy) (proxy.Dialer, string) {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// 1. Пре-фильтр маршрута
	routeFilter := ProxyEntry{Exclude: route.Exclude, Only: route.Only}
	if use, reason := shouldUseProxy(host, routeFilter); !use {
		return proxy.Direct, "route-" + reason
	}

	// 2. Сортировка правил по приоритету (меньше число = выше приоритет)
	type ruleKV struct {
		name     string
		priority int
	}
	var sorted []ruleKV
	for name, rule := range route.Rules {
		sorted = append(sorted, ruleKV{name: name, priority: rule.GetPriority()})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].priority < sorted[j].priority
	})

	// 3. Сбор совпадений: only-совпадения отдельно, exclude/default отдельно
	type match struct {
		name     string
		priority int
		reason   string
	}
	var onlyMatches []match
	var defaultMatches []match

	for _, rkv := range sorted {
		np, ok := proxies[rkv.name]
		if !ok {
			continue
		}
		use, reason := shouldUseProxy(host, np.Entry)
		if !use {
			continue
		}
		if strings.HasPrefix(reason, "only:") {
			onlyMatches = append(onlyMatches, match{name: rkv.name, priority: rkv.priority, reason: reason})
		} else {
			defaultMatches = append(defaultMatches, match{name: rkv.name, priority: rkv.priority, reason: reason})
		}
	}

	// 4. Only-совпадения приоритетнее exclude/default
	if len(onlyMatches) > 0 {
		winner := onlyMatches[0] // уже отсортированы по приоритету
		return proxies[winner.name].Dialer, "route-only:" + winner.name + "(" + winner.reason + ")"
	}

	// 5. Fallback на exclude/default
	if len(defaultMatches) > 0 {
		winner := defaultMatches[0]
		return proxies[winner.name].Dialer, "route-default:" + winner.name + "(" + winner.reason + ")"
	}

	// 6. Ничего не совпало
	return proxy.Direct, "route-no-match"
}

// parseBasicAuth разбирает заголовок формата "Basic <base64>"
func parseBasicAuth(auth string) (username, password string, ok bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return "", "", false
	}
	s := string(decoded)
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return "", "", false
	}
	return s[:colon], s[colon+1:], true
}

// checkRouteAuth проверяет HTTP Proxy-Authorization заголовок запроса.
func checkRouteAuth(r *http.Request, auth *AuthConfig) bool {
	if auth == nil || (auth.Username == "" && auth.Password == "") {
		return true
	}
	username, password, ok := parseBasicAuth(r.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	return username == auth.Username && password == auth.Password
}

func dialContextFrom(d proxy.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.Dial(network, addr)
	}
}

func handleTunneling(w http.ResponseWriter, r *http.Request, d proxy.Dialer) {
	destConn, err := d.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		destConn.Close()
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, bufRW, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}

	_, err = bufRW.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
	if err != nil {
		destConn.Close()
		clientConn.Close()
		return
	}
	bufRW.Flush()

	clientReader := struct {
		io.Reader
		io.Closer
	}{bufRW.Reader, clientConn}

	go transfer(destConn, clientReader)
	go transfer(clientConn, destConn)
}

func handleHTTP(w http.ResponseWriter, req *http.Request, d proxy.Dialer) {
	transport := &http.Transport{
		DialContext:           dialContextFrom(d),
		MaxIdleConns:          100,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   runtime.GOMAXPROCS(0) + 1,
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func buildDialer(entry ProxyEntry) (proxy.Dialer, error) {
	entry.Protocol = normalizeProtocol(entry.Protocol)
	username := entry.GetUsername()
	password := entry.GetPassword()

	switch entry.Protocol {
	case SOCKS5:
		var auth *proxy.Auth
		if username != "" || password != "" {
			auth = &proxy.Auth{User: username, Password: password}
		}
		return proxy.SOCKS5("tcp", entry.Proxy, auth, proxy.Direct)
	case HTTP:
		authHeader := ""
		if username != "" || password != "" {
			token := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
			authHeader = "Basic " + token
		}
		return &httpConnectDialer{address: entry.Proxy, authHeader: authHeader, forward: proxy.Direct}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy protocol %q", entry.Protocol)
	}
}

func runServer(entry ProxyEntry, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	proxyDialer, err := buildDialer(entry)
	if err != nil {
		log.Printf("[%s] failed to create dialer: %v", entry.Dialer, err)
		return
	}

	server := &http.Server{
		Addr: entry.Dialer,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d, reason := dialerFor(r.Host, proxyDialer, entry)
			via := "proxy"
			if d == proxy.Direct {
				via = "direct"
			}
			log.Printf("[%s] %s %s %s → %s (%s)", entry.Dialer, r.RemoteAddr, r.Method, r.Host, via, reason)

			if r.Method == http.MethodConnect {
				handleTunneling(w, r, d)
			} else {
				handleHTTP(w, r, d)
			}
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	go func() {
		<-stop
		server.Shutdown(context.Background())
	}()

	log.Printf("[%s] listening → %s://%s", entry.Dialer, proxyScheme(entry.Protocol), entry.Proxy)
	if len(entry.Only) > 0 {
		log.Printf("[%s] only:    %v", entry.Dialer, entry.Only)
	}
	if len(entry.Exclude) > 0 {
		log.Printf("[%s] exclude: %v", entry.Dialer, entry.Exclude)
	}

	server.ListenAndServe()
}

func runRouteServer(route RouteEntry, proxyMap map[string]NamedProxy, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	server := &http.Server{
		Addr: route.Dialer,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Проверка HTTP Proxy Auth
			if !checkRouteAuth(r, route.Auth) {
				w.Header().Set("Proxy-Authenticate", "Basic realm=\"proxy\"")
				http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
				return
			}

			d, reason := routeRequest(r.Host, route, proxyMap)
			via := "proxy"
			if d == proxy.Direct {
				via = "direct"
			}
			log.Printf("[route:%s] %s %s %s → %s (%s)", route.Dialer, r.RemoteAddr, r.Method, r.Host, via, reason)

			if r.Method == http.MethodConnect {
				handleTunneling(w, r, d)
			} else {
				handleHTTP(w, r, d)
			}
		}),
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	go func() {
		<-stop
		server.Shutdown(context.Background())
	}()

	log.Printf("[route:%s] listening", route.Dialer)
	if len(route.Only) > 0 {
		log.Printf("[route:%s] only:    %v", route.Dialer, route.Only)
	}
	if len(route.Exclude) > 0 {
		log.Printf("[route:%s] exclude: %v", route.Dialer, route.Exclude)
	}
	if route.Auth != nil && route.Auth.Username != "" {
		log.Printf("[route:%s] auth:    required (user=%s)", route.Dialer, route.Auth.Username)
	}
	var ruleDescs []string
	for name, rule := range route.Rules {
		ruleDescs = append(ruleDescs, fmt.Sprintf("%s(p%d)", name, rule.GetPriority()))
	}
	sort.Strings(ruleDescs)
	log.Printf("[route:%s] rules:   %s", route.Dialer, strings.Join(ruleDescs, ", "))

	server.ListenAndServe()
}

// serverGroup управляет группой запущенных серверов (прокси + маршруты).
type serverGroup struct {
	stops []chan struct{}
	wg    sync.WaitGroup
}

func startServers(active ActiveConfig) *serverGroup {
	g := &serverGroup{}

	// Строим карту именованных прокси для маршрутов
	proxyMap := make(map[string]NamedProxy)
	for _, p := range active.Proxies {
		if p.Name == "" {
			continue
		}
		d, err := buildDialer(p)
		if err != nil {
			log.Printf("[routes] failed to build dialer for proxy %q: %v", p.Name, err)
			continue
		}
		proxyMap[p.Name] = NamedProxy{Entry: p, Dialer: d}
	}

	// Запускаем standalone-слушатели (прокси с dialer)
	for _, p := range active.Proxies {
		if p.Dialer == "" {
			continue
		}
		stop := make(chan struct{})
		g.stops = append(g.stops, stop)
		g.wg.Add(1)
		go runServer(p, stop, &g.wg)
	}

	// Запускаем маршруты
	for _, r := range active.Routes {
		stop := make(chan struct{})
		g.stops = append(g.stops, stop)
		g.wg.Add(1)
		go runRouteServer(r, proxyMap, stop, &g.wg)
	}

	return g
}

func (g *serverGroup) stopAll() {
	for _, stop := range g.stops {
		close(stop)
	}
	g.wg.Wait()
}

func configChanged(a, b ActiveConfig) bool {
	if len(a.Proxies) != len(b.Proxies) || len(a.Routes) != len(b.Routes) {
		return true
	}
	set := make(map[string]struct{}, len(a.Proxies)+len(a.Routes))
	for i := range a.Proxies {
		set["p:"+a.Proxies[i].configHash()] = struct{}{}
	}
	for i := range b.Proxies {
		if _, ok := set["p:"+b.Proxies[i].configHash()]; !ok {
			return true
		}
	}
	for i := range a.Routes {
		set["r:"+a.Routes[i].configHash()] = struct{}{}
	}
	for i := range b.Routes {
		if _, ok := set["r:"+b.Routes[i].configHash()]; !ok {
			return true
		}
	}
	return false
}

func watchConfigModify(watcher *fsnotify.Watcher, configFile string, notify chan<- struct{}) {
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					time.Sleep(100 * time.Millisecond)
					log.Println("config modified:", event.Name)
					select {
					case notify <- struct{}{}:
					default:
					}
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("watcher error:", err)
			}
		}
	}()
	if err := watcher.Add(configFile); err != nil {
		log.Fatal(err)
	}
}

func main() {
	configFile := getConfigFile()

	active, err := getActiveConfig(configFile)
	if err != nil {
		log.Fatal(err)
	}
	if len(active.Proxies) == 0 && len(active.Routes) == 0 {
		log.Fatal("no active proxies or routes in config")
	}

	group := startServers(active)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGHUP)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	modify := make(chan struct{}, 1)
	watchConfigModify(watcher, configFile, modify)

	fmt.Println("Running. Press Ctrl+C to exit. Send SIGHUP to reload config.")

	for {
		select {
		case sig := <-sigs:
			if sig == syscall.SIGHUP {
				log.Println("SIGHUP received, reloading config...")
				select {
				case modify <- struct{}{}:
				default:
				}
				continue
			}
			log.Println("shutting down...")
			group.stopAll()
			return

		case <-modify:
			next, err := getActiveConfig(configFile)
			if err != nil {
				log.Printf("config reload error: %v, keeping current config", err)
				continue
			}
			if len(next.Proxies) == 0 && len(next.Routes) == 0 {
				log.Println("config reload: no active proxies or routes, keeping current config")
				continue
			}
			if configChanged(active, next) {
				log.Printf("config changed: restarting servers")
				group.stopAll()
				active = next
				group = startServers(active)
			} else {
				log.Println("config reloaded: no changes detected")
			}
		}
	}
}
