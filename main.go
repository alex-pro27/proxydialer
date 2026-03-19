//go:build ignore

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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
)

const defaultConfigFileName = "config.yaml"

// ProxyEntry описывает одну запись прокси в конфиге.
type ProxyEntry struct {
	Dialer   string   `yaml:"dialer"`   // локальный адрес слушателя, например 127.0.0.1:7492
	Proxy    string   `yaml:"proxy"`    // адрес удалённого прокси, например 85.193.81.230:1818
	Protocol Protocol `yaml:"protocol"` // только "socks5"
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	Use      bool     `yaml:"use"`
	Exclude  []string `yaml:"exclude"` // домены, которые обходят прокси напрямую
	Only     []string `yaml:"only"`    // домены, которые идут ТОЛЬКО через прокси; всё остальное — напрямую
}

// configHash возвращает строку-отпечаток конфигурации для обнаружения изменений.
func (e *ProxyEntry) configHash() string {
	return fmt.Sprintf("%s|%s|%s|%s|%s|%v|%v|%v",
		e.Dialer, e.Proxy, e.Protocol, e.Username, e.Password, e.Use, e.Exclude, e.Only)
}

// Config — корневой тип конфигурационного файла.
type Config struct {
	Version string       `yaml:"version"`
	Proxies []ProxyEntry `yaml:"proxies"`
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
		// *.openai.com совпадает с любым поддоменом и с самим openai.com
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

func parseConfig(configFile string) Config {
	data, err := os.ReadFile(configFile)
	if err != nil {
		panic(fmt.Sprintf("cannot read config: %v", err))
	}
	var conf Config
	if err := yaml.Unmarshal(data, &conf); err != nil {
		panic(fmt.Sprintf("cannot parse config: %v", err))
	}
	return conf
}

func getActiveProxies(configFile string) []ProxyEntry {
	conf := parseConfig(configFile)
	var active []ProxyEntry
	for _, p := range conf.Proxies {
		if !p.Use {
			continue
		}
		if p.Protocol != SOCKS5 {
			log.Printf("skip proxy %s: protocol %q not supported (only socks5)", p.Proxy, p.Protocol)
			continue
		}
		active = append(active, p)
	}
	return active
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
	var auth *proxy.Auth
	if entry.Username != "" || entry.Password != "" {
		auth = &proxy.Auth{User: entry.Username, Password: entry.Password}
	}
	return proxy.SOCKS5("tcp", entry.Proxy, auth, proxy.Direct)
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

	log.Printf("[%s] listening → socks5://%s", entry.Dialer, entry.Proxy)
	if len(entry.Only) > 0 {
		log.Printf("[%s] only:    %v", entry.Dialer, entry.Only)
	}
	if len(entry.Exclude) > 0 {
		log.Printf("[%s] exclude: %v", entry.Dialer, entry.Exclude)
	}

	server.ListenAndServe()
}

// serverGroup управляет группой запущенных серверов.
type serverGroup struct {
	entries []ProxyEntry
	stops   []chan struct{}
	wg      sync.WaitGroup
}

func startServers(entries []ProxyEntry) *serverGroup {
	g := &serverGroup{entries: entries}
	for _, entry := range entries {
		stop := make(chan struct{})
		g.stops = append(g.stops, stop)
		g.wg.Add(1)
		go runServer(entry, stop, &g.wg)
	}
	return g
}

func (g *serverGroup) stopAll() {
	for _, stop := range g.stops {
		close(stop)
	}
	g.wg.Wait()
}

func entriesChanged(a, b []ProxyEntry) bool {
	if len(a) != len(b) {
		return true
	}
	set := make(map[string]struct{}, len(a))
	for _, e := range a {
		set[e.configHash()] = struct{}{}
	}
	for _, e := range b {
		if _, ok := set[e.configHash()]; !ok {
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
					default: // уже есть ожидающее уведомление
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

	entries := getActiveProxies(configFile)
	if len(entries) == 0 {
		log.Fatal("no active proxies in config")
	}

	group := startServers(entries)

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
			next := getActiveProxies(configFile)
			if len(next) == 0 {
				log.Println("config reload: no active proxies, keeping current config")
				continue
			}
			if entriesChanged(entries, next) {
				log.Printf("config changed: stopping %d server(s), starting %d", len(entries), len(next))
				group.stopAll()
				entries = next
				group = startServers(entries)
			} else {
				log.Println("config reloaded: no changes detected")
			}
		}
	}
}
