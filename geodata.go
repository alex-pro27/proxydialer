package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

const (
	defaultGeoIPURL   = "https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/geoip.dat"
	defaultGeoSiteURL = "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"
	defaultGeoDataDir = "/tmp"
)

// GeoDataConfig описывает опциональную секцию geodata в конфиге.
type GeoDataConfig struct {
	Dir     string `yaml:"dir,omitempty"`     // каталог для хранения .dat файлов (по умолчанию /tmp)
	GeoIP   string `yaml:"geoip,omitempty"`   // URL geoip.dat (переопределение)
	GeoSite string `yaml:"geosite,omitempty"` // URL dlc.dat (переопределение)
}

func (c *GeoDataConfig) dir() string {
	if c != nil && c.Dir != "" {
		return c.Dir
	}
	return defaultGeoDataDir
}

func (c *GeoDataConfig) geoIPURL() string {
	if c != nil && c.GeoIP != "" {
		return c.GeoIP
	}
	return defaultGeoIPURL
}

func (c *GeoDataConfig) geoSiteURL() string {
	if c != nil && c.GeoSite != "" {
		return c.GeoSite
	}
	return defaultGeoSiteURL
}

// geodataSame сравнивает две конфигурации geodata.
func geodataSame(a, b *GeoDataConfig) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.dir() == b.dir() && a.geoIPURL() == b.geoIPURL() && a.geoSiteURL() == b.geoSiteURL()
}

type geoDomainType int

const (
	geoDomainPlain geoDomainType = iota
	geoDomainRegex
	geoDomainRoot
	geoDomainFull
)

type geoDomainRule struct {
	typ   geoDomainType
	value string
	re    *regexp.Regexp
}

// geoSiteMatcher матчит домен против списка правил geosite.
type geoSiteMatcher struct {
	rules []geoDomainRule
}

func (m *geoSiteMatcher) match(host string) bool {
	for _, r := range m.rules {
		switch r.typ {
		case geoDomainPlain:
			if strings.Contains(host, r.value) {
				return true
			}
		case geoDomainRegex:
			if r.re != nil && r.re.MatchString(host) {
				return true
			}
		case geoDomainRoot:
			if host == r.value || strings.HasSuffix(host, "."+r.value) {
				return true
			}
		case geoDomainFull:
			if host == r.value {
				return true
			}
		}
	}
	return false
}

// geoIPMatcher матчит IP против списка CIDR из geoip.
type geoIPMatcher struct {
	nets    []*net.IPNet
	inverse bool
}

func (m *geoIPMatcher) match(ip net.IP) bool {
	if ip == nil {
		return false
	}
	matched := false
	for _, n := range m.nets {
		if n.Contains(ip) {
			matched = true
			break
		}
	}
	if m.inverse {
		return !matched
	}
	return matched
}

type geoSnapshot struct {
	sites map[string]*geoSiteMatcher
	ips   map[string]*geoIPMatcher
}

var geoStore atomic.Value // хранит *geoSnapshot

// collectGeoRefs собирает имена списков geosite:/geoip:, упомянутых в правилах
// only/exclude всех прокси и маршрутов.
func collectGeoRefs(proxies []ProxyEntry, routes []RouteEntry) (geoSite, geoIP map[string]bool) {
	geoSite = make(map[string]bool)
	geoIP = make(map[string]bool)
	add := func(entries []string) {
		for _, e := range entries {
			switch {
			case strings.HasPrefix(e, "geosite:"):
				if name := strings.ToLower(strings.TrimSpace(e[len("geosite:"):])); name != "" {
					geoSite[name] = true
				}
			case strings.HasPrefix(e, "geoip:"):
				if name := strings.ToLower(strings.TrimSpace(e[len("geoip:"):])); name != "" {
					geoIP[name] = true
				}
			}
		}
	}
	for i := range proxies {
		add(proxies[i].Only)
		add(proxies[i].Exclude)
	}
	for i := range routes {
		add(routes[i].Only)
		add(routes[i].Exclude)
	}
	return geoSite, geoIP
}

func setEqual(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// loadGeoData скачивает (при необходимости) и загружает только те списки geoip/geosite,
// которые реально упомянуты в конфиге. Если geo-правил нет — ничего не качает.
func loadGeoData(cfg *GeoDataConfig, geoSiteWanted, geoIPWanted map[string]bool) error {
	sites := map[string]*geoSiteMatcher{}
	ips := map[string]*geoIPMatcher{}

	if len(geoSiteWanted) == 0 && len(geoIPWanted) == 0 {
		geoStore.Store(&geoSnapshot{sites: sites, ips: ips})
		log.Println("geodata: no geosite/geoip rules in config, skipping load")
		return nil
	}

	dir := cfg.dir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	if len(geoSiteWanted) > 0 {
		sitePath := filepath.Join(dir, "dlc.dat")
		if err := ensureGeoFile(sitePath, cfg.geoSiteURL()); err != nil {
			return err
		}
		var err error
		if sites, err = loadGeoSites(sitePath, geoSiteWanted); err != nil {
			return err
		}
	}

	if len(geoIPWanted) > 0 {
		ipPath := filepath.Join(dir, "geoip.dat")
		if err := ensureGeoFile(ipPath, cfg.geoIPURL()); err != nil {
			return err
		}
		var err error
		if ips, err = loadGeoIPs(ipPath, geoIPWanted); err != nil {
			return err
		}
	}

	geoStore.Store(&geoSnapshot{sites: sites, ips: ips})
	log.Printf("geodata: loaded %d geosite lists and %d geoip lists from %s", len(sites), len(ips), dir)
	return nil
}

// ensureGeoFile скачивает файл, если его ещё нет на диске или если он был
// скачан с другого URL (источник хранится в sidecar-файле "<path>.url").
func ensureGeoFile(path, url string) error {
	if geoFileFresh(path, url) {
		return nil
	}
	log.Printf("geodata: downloading %s", url)
	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return writeGeoSource(path, url)
}

// geoFileFresh проверяет, что файл существует и скачан с того же URL.
func geoFileFresh(path, url string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	data, err := os.ReadFile(geoSourcePath(path))
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(data)) == url
}

func geoSourcePath(path string) string {
	return path + ".url"
}

func writeGeoSource(path, url string) error {
	return os.WriteFile(geoSourcePath(path), []byte(url+"\n"), 0o644)
}

// forEachEntry вызывает fn для каждой length-delimited записи (field 1) в protobuf.
// Позволяет разбирать .dat потоково, не удерживая весь список в памяти.
func forEachEntry(data []byte, fn func(entry []byte) error) error {
	for len(data) > 0 {
		num, typ, n := protowire.ConsumeTag(data)
		if n < 0 {
			return fmt.Errorf("invalid protobuf tag")
		}
		data = data[n:]
		if num == 1 && typ == protowire.BytesType {
			v, n := protowire.ConsumeBytes(data)
			if n < 0 {
				return fmt.Errorf("invalid protobuf bytes")
			}
			data = data[n:]
			if err := fn(v); err != nil {
				return err
			}
		} else {
			n := protowire.ConsumeFieldValue(num, typ, data)
			if n < 0 {
				return fmt.Errorf("invalid protobuf field")
			}
			data = data[n:]
		}
	}
	return nil
}

// loadGeoSites разбирает dlc.dat (GeoSiteList) в map[name]*geoSiteMatcher,
// загружая только списки из wanted.
func loadGeoSites(path string, wanted map[string]bool) (map[string]*geoSiteMatcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	sites := make(map[string]*geoSiteMatcher)
	err = forEachEntry(data, func(entry []byte) error {
		var e routercommon.GeoSite
		if err := proto.Unmarshal(entry, &e); err != nil {
			return fmt.Errorf("parse geosite %s: %w", path, err)
		}
		name := geoEntryName(e.GetCountryCode(), e.GetCode())
		if name == "" || !wanted[name] {
			return nil
		}
		m := &geoSiteMatcher{}
		for _, d := range e.GetDomain() {
			rule := geoDomainRule{value: strings.ToLower(strings.TrimSpace(d.GetValue()))}
			switch d.GetType() {
			case routercommon.Domain_RootDomain:
				rule.typ = geoDomainRoot
			case routercommon.Domain_Full:
				rule.typ = geoDomainFull
			case routercommon.Domain_Regex:
				rule.typ = geoDomainRegex
				if re, err := regexp.Compile(rule.value); err == nil {
					rule.re = re
				}
			default: // Domain_Plain
				rule.typ = geoDomainPlain
			}
			m.rules = append(m.rules, rule)
		}
		sites[name] = m
		return nil
	})
	if err != nil {
		return nil, err
	}
	return sites, nil
}

// loadGeoIPs разбирает geoip.dat (GeoIPList) в map[name]*geoIPMatcher,
// загружая только списки из wanted.
func loadGeoIPs(path string, wanted map[string]bool) (map[string]*geoIPMatcher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	ips := make(map[string]*geoIPMatcher)
	err = forEachEntry(data, func(entry []byte) error {
		var e routercommon.GeoIP
		if err := proto.Unmarshal(entry, &e); err != nil {
			return fmt.Errorf("parse geoip %s: %w", path, err)
		}
		name := geoEntryName(e.GetCountryCode(), e.GetCode())
		if name == "" || !wanted[name] {
			return nil
		}
		m := &geoIPMatcher{inverse: e.GetInverseMatch()}
		for _, c := range e.GetCidr() {
			if n := cidrToIPNet(c); n != nil {
				m.nets = append(m.nets, n)
			}
		}
		ips[name] = m
		return nil
	})
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func geoEntryName(countryCode, code string) string {
	name := strings.ToLower(strings.TrimSpace(countryCode))
	if name == "" {
		name = strings.ToLower(strings.TrimSpace(code))
	}
	return name
}

// cidrToIPNet преобразует CIDR из protobuf в net.IPNet.
func cidrToIPNet(c *routercommon.CIDR) *net.IPNet {
	ip := net.IP(c.GetIp())
	if ip == nil {
		return nil
	}
	bits := 32
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	} else {
		bits = 128
		ip = ip.To16()
	}
	prefix := int(c.GetPrefix())
	if prefix < 0 || prefix > bits {
		return nil
	}
	mask := net.CIDRMask(prefix, bits)
	return &net.IPNet{IP: ip.Mask(mask), Mask: mask}
}

var warnedGeo sync.Map

func warnUnknownGeo(key string) {
	if _, loaded := warnedGeo.LoadOrStore(key, struct{}{}); !loaded {
		log.Printf("geodata: unknown list %q", key)
	}
}

// matchEntry проверяет host против одного правила: geosite:name, geoip:name или
// обычного домена/wildcard/CIDR.
func matchEntry(host, entry string) bool {
	entry = strings.TrimSpace(entry)
	host = strings.TrimSpace(host)

	switch {
	case strings.HasPrefix(entry, "geosite:"):
		name := strings.ToLower(strings.TrimSpace(entry[len("geosite:"):]))
		snap, _ := geoStore.Load().(*geoSnapshot)
		if snap == nil {
			return false
		}
		m, ok := snap.sites[name]
		if !ok {
			warnUnknownGeo(entry)
			return false
		}
		return m.match(strings.ToLower(host))
	case strings.HasPrefix(entry, "geoip:"):
		name := strings.ToLower(strings.TrimSpace(entry[len("geoip:"):]))
		snap, _ := geoStore.Load().(*geoSnapshot)
		if snap == nil {
			return false
		}
		m, ok := snap.ips[name]
		if !ok {
			warnUnknownGeo(entry)
			return false
		}
		return m.match(net.ParseIP(host))
	default:
		return matchDomain(host, entry)
	}
}
