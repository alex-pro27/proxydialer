package main

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

func mustCIDR(t *testing.T, s string) *net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// --------------- geoSiteMatcher ---------------

func TestGeoSiteMatcher(t *testing.T) {
	re := regexp.MustCompile(`^odd[0-9]+\.example\.org$`)
	m := &geoSiteMatcher{rules: []geoDomainRule{
		{typ: geoDomainRoot, value: "t.me"},
		{typ: geoDomainFull, value: "telegram.org"},
		{typ: geoDomainPlain, value: "telegram"},
		{typ: geoDomainRegex, value: `^odd[0-9]+\.example\.org$`, re: re},
	}}

	tests := []struct {
		host string
		want bool
	}{
		{"t.me", true},
		{"web.t.me", true},
		{"telegram.org", true},
		{"www.telegram.org", true},   // plain substring "telegram"
		{"mytestsite.org", false},    // root "t.me" не совпадает
		{"xtelegramx.com", true},     // plain substring
		{"odd123.example.org", true}, // regex
		{"odd.example.org", false},   // regex не совпадает
		{"unrelated.com", false},
	}
	for _, tt := range tests {
		if got := m.match(tt.host); got != tt.want {
			t.Errorf("geoSiteMatcher.match(%q) = %v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestGeoSiteFullVsRoot(t *testing.T) {
	full := &geoSiteMatcher{rules: []geoDomainRule{{typ: geoDomainFull, value: "telegram.org"}}}
	root := &geoSiteMatcher{rules: []geoDomainRule{{typ: geoDomainRoot, value: "telegram.org"}}}

	if !full.match("telegram.org") {
		t.Error("full should match exact domain")
	}
	if full.match("www.telegram.org") {
		t.Error("full should not match subdomain")
	}
	if !root.match("www.telegram.org") {
		t.Error("root should match subdomain")
	}
}

// --------------- geoIPMatcher ---------------

func TestGeoIPMatcher(t *testing.T) {
	m := &geoIPMatcher{nets: []*net.IPNet{
		mustCIDR(t, "91.108.4.0/22"),
		mustCIDR(t, "2001:67c:4e8::/48"),
	}}

	if !m.match(net.ParseIP("91.108.4.25")) {
		t.Error("91.108.4.25 should match")
	}
	if m.match(net.ParseIP("91.108.8.1")) {
		t.Error("91.108.8.1 should not match")
	}
	if !m.match(net.ParseIP("2001:67c:4e8::1")) {
		t.Error("2001:67c:4e8::1 should match")
	}
	if m.match(net.ParseIP("2001:67c:4e9::1")) {
		t.Error("2001:67c:4e9::1 should not match")
	}
	if m.match(nil) {
		t.Error("nil IP should not match")
	}
}

func TestGeoIPMatcherInverse(t *testing.T) {
	m := &geoIPMatcher{
		inverse: true,
		nets:    []*net.IPNet{mustCIDR(t, "10.0.0.0/8")},
	}
	if m.match(net.ParseIP("10.1.2.3")) {
		t.Error("inverse: IP inside range should not match")
	}
	if !m.match(net.ParseIP("8.8.8.8")) {
		t.Error("inverse: IP outside range should match")
	}
}

// --------------- loadGeoSites ---------------

func TestLoadGeoSites(t *testing.T) {
	list := &routercommon.GeoSiteList{
		Entry: []*routercommon.GeoSite{
			{
				CountryCode: "telegram",
				Domain: []*routercommon.Domain{
					{Type: routercommon.Domain_RootDomain, Value: "t.me"},
					{Type: routercommon.Domain_Full, Value: "telegram.org"},
					{Type: routercommon.Domain_Plain, Value: "telegram"},
					{Type: routercommon.Domain_Regex, Value: `^odd[0-9]+\.example\.org$`},
				},
			},
		},
	}
	path := writeProto(t, "geosite-test-*.dat", list)

	sites, err := loadGeoSites(path, map[string]bool{"telegram": true})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := sites["telegram"]
	if !ok {
		t.Fatal("telegram list not found")
	}
	if !m.match("web.t.me") {
		t.Error("web.t.me should match geosite:telegram")
	}
	if !m.match("xtelegramx.com") {
		t.Error("xtelegramx.com should match (plain substring)")
	}
	if m.match("unrelated.com") {
		t.Error("unrelated.com should not match")
	}
}

// --------------- loadGeoIPs ---------------

func TestLoadGeoIPs(t *testing.T) {
	list := &routercommon.GeoIPList{
		Entry: []*routercommon.GeoIP{
			{
				CountryCode: "telegram",
				Cidr: []*routercommon.CIDR{
					{Ip: net.ParseIP("91.108.4.0").To4(), Prefix: 22},
					{Ip: net.ParseIP("2001:67c:4e8::").To16(), Prefix: 48},
				},
			},
			{
				CountryCode:  "private-except",
				InverseMatch: true,
				Cidr: []*routercommon.CIDR{
					{Ip: net.ParseIP("10.0.0.0").To4(), Prefix: 8},
				},
			},
		},
	}
	path := writeProto(t, "geoip-test-*.dat", list)

	ips, err := loadGeoIPs(path, map[string]bool{"telegram": true, "private-except": true})
	if err != nil {
		t.Fatal(err)
	}
	m, ok := ips["telegram"]
	if !ok {
		t.Fatal("telegram list not found")
	}
	if !m.match(net.ParseIP("91.108.4.25")) {
		t.Error("91.108.4.25 should match geoip:telegram")
	}
	if !m.match(net.ParseIP("2001:67c:4e8::1")) {
		t.Error("2001:67c:4e8::1 should match geoip:telegram")
	}
	if m.match(net.ParseIP("91.108.8.1")) {
		t.Error("91.108.8.1 should not match geoip:telegram")
	}

	inv, ok := ips["private-except"]
	if !ok {
		t.Fatal("private-except list not found")
	}
	if inv.match(net.ParseIP("10.1.2.3")) {
		t.Error("inverse list should not match in-range IP")
	}
	if !inv.match(net.ParseIP("8.8.8.8")) {
		t.Error("inverse list should match out-of-range IP")
	}
}

func TestLoadGeoIPsSelective(t *testing.T) {
	list := &routercommon.GeoIPList{
		Entry: []*routercommon.GeoIP{
			{CountryCode: "telegram", Cidr: []*routercommon.CIDR{{Ip: net.ParseIP("91.108.4.0").To4(), Prefix: 22}}},
			{CountryCode: "google", Cidr: []*routercommon.CIDR{{Ip: net.ParseIP("8.8.8.0").To4(), Prefix: 24}}},
		},
	}
	path := writeProto(t, "geoip-sel-*.dat", list)

	ips, err := loadGeoIPs(path, map[string]bool{"telegram": true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ips["telegram"]; !ok {
		t.Error("telegram should be loaded")
	}
	if _, ok := ips["google"]; ok {
		t.Error("google should NOT be loaded (not in wanted)")
	}
}

func TestLoadGeoSitesSelective(t *testing.T) {
	list := &routercommon.GeoSiteList{
		Entry: []*routercommon.GeoSite{
			{CountryCode: "telegram", Domain: []*routercommon.Domain{{Type: routercommon.Domain_RootDomain, Value: "t.me"}}},
			{CountryCode: "google", Domain: []*routercommon.Domain{{Type: routercommon.Domain_RootDomain, Value: "google.com"}}},
		},
	}
	path := writeProto(t, "geosite-sel-*.dat", list)

	sites, err := loadGeoSites(path, map[string]bool{"telegram": true})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sites["telegram"]; !ok {
		t.Error("telegram should be loaded")
	}
	if _, ok := sites["google"]; ok {
		t.Error("google should NOT be loaded (not in wanted)")
	}
}

func TestCollectGeoRefs(t *testing.T) {
	proxies := []ProxyEntry{
		{Only: []string{"geosite:telegram", "geoip:telegram"}, Exclude: []string{"*.example.com"}},
	}
	routes := []RouteEntry{
		{Exclude: []string{"geoip:google", "geosite: GOOGLE"}},
	}

	gs, gi := collectGeoRefs(proxies, routes)
	if !gs["telegram"] || !gs["google"] {
		t.Errorf("geosite refs = %v, want telegram+google", gs)
	}
	if !gi["telegram"] || !gi["google"] {
		t.Errorf("geoip refs = %v, want telegram+google", gi)
	}
	if len(gs) != 2 || len(gi) != 2 {
		t.Errorf("unexpected refs: geosite=%v geoip=%v", gs, gi)
	}
}

func TestLoadGeoDataSkipWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	cfg := &GeoDataConfig{Dir: dir}

	if err := loadGeoData(cfg, map[string]bool{}, map[string]bool{}); err != nil {
		t.Fatal(err)
	}

	snap, _ := geoStore.Load().(*geoSnapshot)
	if snap == nil || len(snap.sites) != 0 || len(snap.ips) != 0 {
		t.Fatal("expected empty snapshot")
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected no files downloaded, got %d", len(entries))
	}
}

func writeProto(t *testing.T, pattern string, m proto.Message) string {
	t.Helper()
	data, err := proto.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	tmp, err := os.CreateTemp("", pattern)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		t.Fatal(err)
	}
	if err := tmp.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(tmp.Name()) })
	return tmp.Name()
}

// --------------- matchEntry ---------------

func TestMatchEntryDispatch(t *testing.T) {
	geoStore.Store(&geoSnapshot{
		sites: map[string]*geoSiteMatcher{
			"telegram": {rules: []geoDomainRule{{typ: geoDomainRoot, value: "t.me"}}},
		},
		ips: map[string]*geoIPMatcher{
			"telegram": {nets: []*net.IPNet{mustCIDR(t, "91.108.4.0/22")}},
		},
	})
	defer geoStore.Store(&geoSnapshot{})

	tests := []struct {
		host  string
		entry string
		want  bool
	}{
		{"web.t.me", "geosite:telegram", true},
		{"example.com", "geosite:telegram", false},
		{"91.108.4.25", "geoip:telegram", true},
		{"91.108.8.1", "geoip:telegram", false},
		{"api.example.com", "*.example.com", true},
		{"91.108.4.25", "91.108.4.0/22", true},
		{"web.t.me", "geosite:unknown", false},
		{"91.108.4.25", "geoip:unknown", false},
	}

	for _, tt := range tests {
		if got := matchEntry(tt.host, tt.entry); got != tt.want {
			t.Errorf("matchEntry(%q, %q) = %v, want %v", tt.host, tt.entry, got, tt.want)
		}
	}
}

// --------------- geoFileFresh (инвалидация кеша) ---------------

func TestGeoFileFresh(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "geoip.dat")

	if geoFileFresh(path, "https://u1") {
		t.Error("missing file should not be fresh")
	}

	if err := os.WriteFile(path, []byte("data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if geoFileFresh(path, "https://u1") {
		t.Error("file without sidecar should not be fresh")
	}

	if err := writeGeoSource(path, "https://u2"); err != nil {
		t.Fatal(err)
	}
	if geoFileFresh(path, "https://u1") {
		t.Error("file with different source url should not be fresh")
	}

	if err := writeGeoSource(path, "https://u1"); err != nil {
		t.Fatal(err)
	}
	if !geoFileFresh(path, "https://u1") {
		t.Error("file with matching source url should be fresh")
	}
}

// --------------- shouldUseProxy с geosite/geoip ---------------

func TestShouldUseProxyGeo(t *testing.T) {
	geoStore.Store(&geoSnapshot{
		sites: map[string]*geoSiteMatcher{
			"telegram": {rules: []geoDomainRule{{typ: geoDomainRoot, value: "t.me"}}},
		},
		ips: map[string]*geoIPMatcher{
			"telegram": {nets: []*net.IPNet{mustCIDR(t, "91.108.4.0/22")}},
		},
	})
	defer geoStore.Store(&geoSnapshot{})

	// only: geosite
	e := ProxyEntry{Only: []string{"geosite:telegram"}}
	if use, reason := shouldUseProxy("web.t.me", e); !use || reason != "only:geosite:telegram" {
		t.Errorf("web.t.me → use=%v reason=%q", use, reason)
	}
	if use, _ := shouldUseProxy("example.com", e); use {
		t.Error("example.com should not match geosite only")
	}

	// exclude: geoip
	e2 := ProxyEntry{Exclude: []string{"geoip:telegram"}}
	if use, reason := shouldUseProxy("91.108.4.25", e2); use || reason != "exclude:geoip:telegram" {
		t.Errorf("91.108.4.25 → use=%v reason=%q", use, reason)
	}
	if use, _ := shouldUseProxy("8.8.8.8", e2); !use {
		t.Error("8.8.8.8 should not be excluded")
	}
}
