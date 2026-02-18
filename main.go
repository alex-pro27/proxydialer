package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"hash/fnv"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"runtime"
	"time"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/net/proxy"
	"gopkg.in/yaml.v3"
)

type Protocol string

const (
	SOCKS5 Protocol = "socks5"
)

const DEFAULT_CONFIG_FILE_NAME = "config.yaml"

func getHash(s string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(s))
	return h.Sum32()
}

type DialerConfig struct {
	Server string `yaml:"server"`
	Port   int    `yaml:"port"`
}

func (config *DialerConfig) getDialerConfHash() uint32 {
	str := fmt.Sprintf("%s:%d", config.Server, config.Port)
	return getHash(str)
}

type ProxyConf struct {
	Protocol Protocol `yaml:"protocol"`
	Server   string   `yaml:"server"`
	Port     int      `yaml:"port"`
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	Use      bool     `yaml:"use"`
}

func (config *ProxyConf) getProxyConfHash() uint32 {
	str := fmt.Sprintf("%s//:%s:%s@%s:%d", config.Protocol, config.Username, config.Password, config.Server, config.Port)
	return getHash(str)
}

type Config struct {
	Version string       `yaml:"version"`
	Dialer  DialerConfig `yaml:"dialer"`
	Proxies []ProxyConf  `yaml:"proxies"`
}

type DialContext func(ctx context.Context, network, address string) (net.Conn, error)

func getConfigFile() string {
	configFile, ok := os.LookupEnv("PROXY_DEALER_CONFIG_FILE")
	if !ok {
		_, filename, _, _ := runtime.Caller(1)
		configFile = path.Join(path.Dir(filename), DEFAULT_CONFIG_FILE_NAME)
	}
	return configFile
}

func parseConfig(configFile string) Config {
	conf := Config{}
	data, err := os.ReadFile(configFile)
	if err != nil {
		panic(err)
	}
	err1 := yaml.Unmarshal(data, &conf)
	if err1 != nil {
		panic(err1)
	}
	return conf
}

func getProxyConfig(configFile string) (*DialerConfig, *ProxyConf) {
	config := parseConfig(configFile)

	var proxyConf *ProxyConf = nil

	for _, conf := range config.Proxies {
		if conf.Use {
			if conf.Protocol != SOCKS5 {
				panic("Only SOCKS5 protocol is supported")
			}
			proxyConf = &conf
		}
	}

	return &config.Dialer, proxyConf
}

// establishSOCKS5Proxy establishes a connection to the SOCKS5 proxy server
func establishSOCKS5Proxy(socks5Addr string, auth *proxy.Auth) (proxy.Dialer, error) {
	// Create a socks5 dialer
	return proxy.SOCKS5("tcp", socks5Addr, auth, proxy.Direct)
}

func getDialContext(dialer proxy.Dialer) DialContext {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.Dial(network, address)
	}
}

// getHandleTunneling handles CONNECT requests
func getHandleTunneling(dialer proxy.Dialer) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		dest_conn, err := dialer.Dial("tcp", r.Host)

		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		hijacker, ok := w.(http.Hijacker)
		if !ok {
			dest_conn.Close()
			http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
			return
		}
		client_conn, bufRW, err := hijacker.Hijack()
		if err != nil {
			dest_conn.Close()
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}

		_, err = bufRW.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
		if err != nil {
			dest_conn.Close()
			client_conn.Close()
			return
		}
		bufRW.Flush()

		clientReader := struct {
			io.Reader
			io.Closer
		}{bufRW.Reader, client_conn}

		go transfer(dest_conn, clientReader)
		go transfer(client_conn, dest_conn)
	}
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer func() {
		if destination != nil {
			destination.Close()
		}
		if source != nil {
			source.Close()
		}
	}()
	if destination != nil && source != nil {
		io.Copy(destination, source)
	}
}

// getHandleHTTP handles normal HTTP requests
func getHandleHTTP(dialer proxy.Dialer) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		//resp, err := http.DefaultTransport.RoundTrip(req)
		//if err != nil {
		//	http.Error(w, err.Error(), http.StatusServiceUnavailable)
		//	return
		//}
		transport := &http.Transport{
			DialContext:           getDialContext(dialer),
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
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func runServer(dialerConfig DialerConfig, proxyConfig ProxyConf, stop chan int) {

	var auth *proxy.Auth
	proxyAddr := fmt.Sprintf("%s:%d", proxyConfig.Server, proxyConfig.Port)
	if proxyConfig.Username != "" && proxyConfig.Password != "" {
		auth = &proxy.Auth{
			User:     proxyConfig.Username,
			Password: proxyConfig.Password,
		}
	}

	dialer, err := establishSOCKS5Proxy(proxyAddr, auth)
	if err != nil {
		log.Fatalf("Error: %s", err.Error())
		return
	}
	handleTunneling := getHandleTunneling(dialer)
	handleHTTP := getHandleHTTP(dialer)
	serverAddr := fmt.Sprintf("%s:%d", dialerConfig.Server, dialerConfig.Port)
	server := &http.Server{
		Addr: serverAddr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log.Printf("%s %s %s", r.RemoteAddr, r.Method, r.URL)
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	go func() {
		<-stop
		server.Shutdown(context.Background())
	}()

	log.Println("Server is running on http://" + serverAddr)
	log.Println("Dialer to on socks5://" + proxyAddr)
	server.ListenAndServe()
}

func watchConfigModify(watcher *fsnotify.Watcher, configFile string, notify chan int) {
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) {
					time.Sleep(100 * time.Millisecond)
					log.Println("modified file:", event.Name)
					notify <- 1
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Println("watch file error:", err)
			}

		}
	}()
	err := watcher.Add(configFile)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {

	configFile := getConfigFile()

	stop := make(chan int)
	modify := make(chan int)

	dialerConfig, proxyConfig := getProxyConfig(configFile)
	if proxyConfig == nil {
		log.Fatal("No proxy configured")
	}
	go runServer(*dialerConfig, *proxyConfig, stop)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}

	defer watcher.Close()

	go func() {
		for {
			<-modify
			nextDialerConfig, nextProxyConfig := getProxyConfig(configFile)
			if nextProxyConfig == nil {
				log.Println("No found proxy configured")
				continue
			}
			if nextDialerConfig.getDialerConfHash() != dialerConfig.getDialerConfHash() ||
				nextProxyConfig.getProxyConfHash() != proxyConfig.getProxyConfHash() {
				stop <- 1
				go runServer(*nextDialerConfig, *nextProxyConfig, stop)
				dialerConfig = nextDialerConfig
				proxyConfig = nextProxyConfig
			} else {
				log.Println("No change in proxy configuration")
			}
		}
	}()

	watchConfigModify(watcher, configFile, modify)

	fmt.Printf("For exit press ctrl + C again.\n")

	<-sigs
}
