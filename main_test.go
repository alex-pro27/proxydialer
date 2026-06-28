package main

import (
	"net"
	"net/http"
	"os"
	"strings"
	"testing"

	"golang.org/x/net/proxy"
)

// testDialer реализует proxy.Dialer для проверки роутинга без реальных соединений.
type testDialer struct {
	name string
}

func (d testDialer) Dial(network, addr string) (net.Conn, error) { return nil, nil }

// --------------- matchDomain ---------------

func TestMatchDomain(t *testing.T) {
	tests := []struct {
		host    string
		domain  string
		want    bool
	}{
		// точное совпадение
		{"example.com", "example.com", true},
		// поддомен
		{"api.example.com", "example.com", true},
		// вложенный поддомен
		{"foo.bar.example.com", "example.com", true},
		// wildcard — любой поддомен
		{"api.example.com", "*.example.com", true},
		{"foo.bar.example.com", "*.example.com", true},
		// wildcard — сам базовый домен
		{"example.com", "*.example.com", true},
		// wildcard — без совпадения
		{"other.com", "*.example.com", false},
		// несовпадение
		{"other.com", "example.com", false},
		{"example.org", "example.com", false},
		// case‑insensitive
		{"EXAMPLE.COM", "example.com", true},
		{"example.com", "EXAMPLE.COM", true},
		{"Api.Example.Com", "*.example.com", true},
		// wildcard без точки — не wildcard
		{"*example.com", "example.com", false},
		// IP адреса
		{"10.248.1.79", "10.248.1.79", true},
		// пробелы
		{"  example.com  ", "example.com", true},
	}

	for _, tt := range tests {
		got := matchDomain(tt.host, tt.domain)
		if got != tt.want {
			t.Errorf("matchDomain(%q, %q) = %v, want %v", tt.host, tt.domain, got, tt.want)
		}
	}
}

// --------------- shouldUseProxy ---------------

func TestShouldUseProxy(t *testing.T) {
	tests := []struct {
		name       string
		host       string
		only       []string
		exclude    []string
		wantUse    bool
		wantReason string
	}{
		// only
		{"only‑match", "api.openai.com", []string{"*.openai.com"}, nil, true, "only:*.openai.com"},
		{"only‑no‑match", "example.com", []string{"*.openai.com"}, nil, false, "not-in-only"},
		// exclude
		{"exclude‑match‑reject", "yandex.ru", nil, []string{"*.yandex.ru"}, false, "exclude:*.yandex.ru"},
		{"exclude‑no‑match", "example.com", nil, []string{"*.yandex.ru"}, true, "default"},
		// both
		{"both‑pass", "api.openai.com", []string{"*.openai.com"}, []string{"*.yandex.ru"}, true, "only:*.openai.com"},
		{"both‑reject", "api.openai.com", []string{"*.openai.com"}, []string{"*.openai.com"}, false, "only+exclude:*.openai.com"},
		// neither
		{"no‑rules", "example.com", nil, nil, true, "default"},
		// host с портом
		{"host‑with‑port", "example.com:443", nil, nil, true, "default"},
		// only с портом
		{"only‑match‑port", "api.openai.com:443", []string{"*.openai.com"}, nil, true, "only:*.openai.com"},
		// exclude с портом
		{"exclude‑match‑port", "yandex.ru:443", nil, []string{"*.yandex.ru"}, false, "exclude:*.yandex.ru"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := ProxyEntry{Only: tt.only, Exclude: tt.exclude}
			use, reason := shouldUseProxy(tt.host, e)
			if use != tt.wantUse {
				t.Errorf("use = %v, want %v", use, tt.wantUse)
			}
			if reason != tt.wantReason {
				t.Errorf("reason = %q, want %q", reason, tt.wantReason)
			}
		})
	}
}

// --------------- routeRequest ---------------

func TestRouteRequest(t *testing.T) {
	spbDialer := testDialer{name: "spb"}
	usDialer := testDialer{name: "us"}

	// Прокси: SPB — exclude‑based (всё, кроме указанного), US — only‑based (только указанное)
	proxyMap := map[string]NamedProxy{
		"SPB": {Entry: ProxyEntry{
			Name:    "SPB",
			Exclude: []string{"*.yandex.ru"},
		}, Dialer: spbDialer},
		"US (Microsoft, GitHub, OpenAI)": {Entry: ProxyEntry{
			Name: "US",
			Only: []string{"*.github.com", "*.openai.com"},
		}, Dialer: usDialer},
	}

	route := RouteEntry{
		Exclude: []string{"*.microsoft.com"},
		Rules: map[string]RouteRule{
			"SPB":                           {Priority: 1},
			"US (Microsoft, GitHub, OpenAI)": {Priority: 2},
		},
	}

	tests := []struct {
		name       string
		host       string
		wantDialer string   // "spb", "us", "direct"
		wantReasonPrefix string
	}{
		{"route‑exclude blocks", "microsoft.com", "direct", "route-exclude:"},
		{"only‑match wins over default", "github.com", "us", "route-only:"},
		{"only‑match other", "api.openai.com", "us", "route-only:"},
		{"default fallback SPB", "example.com", "spb", "route-default:"},
		{"no proxy matches", "yandex.ru", "direct", "route-no-match"},
		{"host with port only-match", "github.com:443", "us", "route-only:"},
		{"host with port default", "example.com:443", "spb", "route-default:"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, reason := routeRequest(tt.host, route, proxyMap)
			if !strings.HasPrefix(reason, tt.wantReasonPrefix) {
				t.Errorf("reason = %q, want prefix %q", reason, tt.wantReasonPrefix)
			}
			switch tt.wantDialer {
			case "direct":
				if d != proxy.Direct {
					t.Errorf("expected proxy.Direct, got %v", d)
				}
			case "spb":
				td, ok := d.(testDialer)
				if !ok || td.name != "spb" {
					t.Errorf("expected spb dialer, got %v", d)
				}
			case "us":
				td, ok := d.(testDialer)
				if !ok || td.name != "us" {
					t.Errorf("expected us dialer, got %v", d)
				}
			}
		})
	}
}

// --------------- route only‑pre‑filter ---------------

func TestRouteRequestOnlyPreFilter(t *testing.T) {
	spbDialer := testDialer{name: "spb"}
	proxyMap := map[string]NamedProxy{
		"SPB": {Entry: ProxyEntry{Name: "SPB"}, Dialer: spbDialer},
	}

	route := RouteEntry{
		Only: []string{"*.example.com"},
		Rules: map[string]RouteRule{
			"SPB": {Priority: 1},
		},
	}

	// Домен в only маршрута — проходит
	d, _ := routeRequest("example.com", route, proxyMap)
	if d == proxy.Direct {
		t.Error("example.com should pass route only‑filter")
	}

	// Домен НЕ в only маршрута — Direct
	d, _ = routeRequest("other.com", route, proxyMap)
	if d != proxy.Direct {
		t.Error("other.com should be blocked by route only‑filter")
	}
}

// --------------- route multiple only‑matches (priority conflict) ---------------

func TestRouteRequestOnlyPriorityConflict(t *testing.T) {
	highDialer := testDialer{name: "high"}
	lowDialer := testDialer{name: "low"}

	// Оба прокси имеют *.github.com в only, но с разными приоритетами
	proxyMap := map[string]NamedProxy{
		"high": {Entry: ProxyEntry{
			Name: "high",
			Only: []string{"*.github.com"},
		}, Dialer: highDialer},
		"low": {Entry: ProxyEntry{
			Name: "low",
			Only: []string{"*.github.com"},
		}, Dialer: lowDialer},
	}

	route := RouteEntry{
		Rules: map[string]RouteRule{
			"high": {Priority: 1},
			"low":  {Priority: 2},
		},
	}

	d, reason := routeRequest("github.com", route, proxyMap)
	if !strings.HasPrefix(reason, "route-only:") {
		t.Errorf("expected route-only reason, got %q", reason)
	}
	td, ok := d.(testDialer)
	if !ok || td.name != "high" {
		t.Errorf("expected high‑priority dialer, got %v", d)
	}
}

// --------------- route multiple default‑matches (priority conflict) ---------------

func TestRouteRequestDefaultPriorityConflict(t *testing.T) {
	highDialer := testDialer{name: "high"}
	lowDialer := testDialer{name: "low"}

	// Оба прокси без правил — оба default‑match
	proxyMap := map[string]NamedProxy{
		"high": {Entry: ProxyEntry{Name: "high"}, Dialer: highDialer},
		"low":  {Entry: ProxyEntry{Name: "low"}, Dialer: lowDialer},
	}

	route := RouteEntry{
		Rules: map[string]RouteRule{
			"high": {Priority: 1},
			"low":  {Priority: 2},
		},
	}

	d, reason := routeRequest("example.com", route, proxyMap)
	if !strings.HasPrefix(reason, "route-default:") {
		t.Errorf("expected route-default reason, got %q", reason)
	}
	td, ok := d.(testDialer)
	if !ok || td.name != "high" {
		t.Errorf("expected high‑priority dialer, got %v", d)
	}
}

// --------------- parseBasicAuth ---------------

func TestParseBasicAuth(t *testing.T) {
	tests := []struct {
		name         string
		header       string
		wantUser     string
		wantPass     string
		wantOk       bool
	}{
		{"valid", "Basic dXNlcjpwYXNz", "user", "pass", true},
		{"empty", "", "", "", false},
		{"wrong prefix", "Bearer dXNlcjpwYXNz", "", "", false},
		{"invalid base64", "Basic !!!", "", "", false},
		{"no colon", "Basic dXNlcg==", "", "", false}, // "user" without colon
		{"empty user", "Basic OnBhc3M=", "", "pass", true}, // ":pass"
		{"empty pass", "Basic dXNlcjo=", "user", "", true}, // "user:"
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, pass, ok := parseBasicAuth(tt.header)
			if ok != tt.wantOk {
				t.Errorf("ok = %v, want %v", ok, tt.wantOk)
			}
			if user != tt.wantUser {
				t.Errorf("user = %q, want %q", user, tt.wantUser)
			}
			if pass != tt.wantPass {
				t.Errorf("pass = %q, want %q", pass, tt.wantPass)
			}
		})
	}
}

// --------------- checkRouteAuth ---------------

func TestCheckRouteAuth(t *testing.T) {
	tests := []struct {
		name       string
		authConfig *AuthConfig
		header     string
		want       bool
	}{
		{"no auth config", nil, "", true},
		{"empty auth config", &AuthConfig{}, "", true},
		{"correct auth", &AuthConfig{Username: "user", Password: "pass"}, "Basic dXNlcjpwYXNz", true},
		{"wrong password", &AuthConfig{Username: "user", Password: "pass"}, "Basic dXNlcjp3cm9uZw==", false},
		{"wrong user", &AuthConfig{Username: "user", Password: "pass"}, "Basic d3Jvbmc6cGFzcw==", false},
		{"missing header", &AuthConfig{Username: "user", Password: "pass"}, "", false},
		{"empty credentials in config", &AuthConfig{Username: "", Password: ""}, "Basic Og==", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			if tt.header != "" {
				req.Header.Set("Proxy-Authorization", tt.header)
			}
			got := checkRouteAuth(req, tt.authConfig)
			if got != tt.want {
				t.Errorf("checkRouteAuth = %v, want %v", got, tt.want)
			}
		})
	}
}

// --------------- GetUsername / GetPassword ---------------

func TestGetUsernamePassword(t *testing.T) {
	// nested auth has priority
	e := ProxyEntry{
		Username: "flat_user",
		Password: "flat_pass",
		Auth:     &AuthConfig{Username: "nested_user", Password: "nested_pass"},
	}
	if e.GetUsername() != "nested_user" {
		t.Errorf("GetUsername = %q, want nested_user", e.GetUsername())
	}
	if e.GetPassword() != "nested_pass" {
		t.Errorf("GetPassword = %q, want nested_pass", e.GetPassword())
	}

	// flat only
	e2 := ProxyEntry{Username: "flat_user", Password: "flat_pass"}
	if e2.GetUsername() != "flat_user" {
		t.Errorf("GetUsername = %q, want flat_user", e2.GetUsername())
	}
	if e2.GetPassword() != "flat_pass" {
		t.Errorf("GetPassword = %q, want flat_pass", e2.GetPassword())
	}

	// empty nested falls back to flat
	e3 := ProxyEntry{
		Username: "flat_user",
		Auth:     &AuthConfig{Username: "", Password: ""},
	}
	if e3.GetUsername() != "flat_user" {
		t.Errorf("GetUsername = %q, want flat_user (fallback)", e3.GetUsername())
	}
}

// --------------- configHash ---------------

func TestProxyEntryConfigHash(t *testing.T) {
	e1 := &ProxyEntry{Dialer: "127.0.0.1:7000", Proxy: "127.0.0.1:9000", Protocol: SOCKS5, Use: true, Name: "test"}
	e2 := &ProxyEntry{Dialer: "127.0.0.1:7000", Proxy: "127.0.0.1:9000", Protocol: SOCKS5, Use: true, Name: "test"}
	if e1.configHash() != e2.configHash() {
		t.Error("identical entries should have same hash")
	}

	e3 := &ProxyEntry{Dialer: "127.0.0.1:7000", Proxy: "127.0.0.1:9000", Protocol: SOCKS5, Use: true, Name: "different"}
	if e1.configHash() == e3.configHash() {
		t.Error("entries with different Name should have different hash")
	}

	// auth affects hash
	e4 := &ProxyEntry{Dialer: "127.0.0.1:7000", Proxy: "127.0.0.1:9000", Protocol: SOCKS5, Use: true, Name: "test",
		Auth: &AuthConfig{Username: "u", Password: "p"}}
	if e1.configHash() == e4.configHash() {
		t.Error("entries with different auth should have different hash")
	}
}

func TestRouteEntryConfigHash(t *testing.T) {
	r1 := &RouteEntry{Dialer: "127.0.0.1:8080", Use: true,
		Rules: map[string]RouteRule{"SPB": {Priority: 1}},
	}
	r2 := &RouteEntry{Dialer: "127.0.0.1:8080", Use: true,
		Rules: map[string]RouteRule{"SPB": {Priority: 1}},
	}
	if r1.configHash() != r2.configHash() {
		t.Error("identical routes should have same hash")
	}

	r3 := &RouteEntry{Dialer: "127.0.0.1:8080", Use: true,
		Rules: map[string]RouteRule{"SPB": {Priority: 2}}, // другой приоритет
	}
	if r1.configHash() == r3.configHash() {
		t.Error("routes with different priority should have different hash")
	}
}

// --------------- configChanged ---------------

func TestConfigChanged(t *testing.T) {
	a := ActiveConfig{
		Proxies: []ProxyEntry{{Dialer: "127.0.0.1:7000", Proxy: "127.0.0.1:9000", Protocol: SOCKS5, Use: true}},
		Routes:  []RouteEntry{},
	}
	b := ActiveConfig{
		Proxies: []ProxyEntry{{Dialer: "127.0.0.1:7000", Proxy: "127.0.0.1:9000", Protocol: SOCKS5, Use: true}},
		Routes:  []RouteEntry{},
	}
	if configChanged(a, b) {
		t.Error("identical configs should not trigger change")
	}

	// proxy change
	c := ActiveConfig{
		Proxies: []ProxyEntry{{Dialer: "127.0.0.1:7001", Proxy: "127.0.0.1:9000", Protocol: SOCKS5, Use: true}},
		Routes:  []RouteEntry{},
	}
	if !configChanged(a, c) {
		t.Error("different proxy should trigger change")
	}

	// route change
	d := ActiveConfig{
		Proxies: []ProxyEntry{{Dialer: "127.0.0.1:7000", Proxy: "127.0.0.1:9000", Protocol: SOCKS5, Use: true}},
		Routes:  []RouteEntry{{Dialer: "127.0.0.1:8080", Use: true}},
	}
	if !configChanged(a, d) {
		t.Error("added route should trigger change")
	}

	// different lengths
	e := ActiveConfig{Proxies: nil, Routes: nil}
	if !configChanged(a, e) {
		t.Error("different proxy count should trigger change")
	}
}

// --------------- YAML parsing ---------------

func TestParseConfigFlatAuth(t *testing.T) {
	yaml := `
version: "1"
proxies:
  - dialer: 127.0.0.1:7492
    proxy: 127.0.0.1:6066
    protocol: socks5
    username: user
    password: pass
    use: true
`
	conf, err := parseConfigFromString(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(conf.Proxies))
	}
	p := conf.Proxies[0]
	if p.GetUsername() != "user" {
		t.Errorf("username = %q, want user", p.GetUsername())
	}
	if p.GetPassword() != "pass" {
		t.Errorf("password = %q, want pass", p.GetPassword())
	}
	if p.Name != "" {
		t.Errorf("name should be empty, got %q", p.Name)
	}
}

func TestParseConfigNestedAuth(t *testing.T) {
	yaml := `
version: "1"
proxies:
  - dialer: 127.0.0.1:7492
    proxy: 127.0.0.1:6066
    protocol: socks5
    auth:
      username: nested_user
      password: nested_pass
    use: true
    name: SPB
`
	conf, err := parseConfigFromString(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Proxies) != 1 {
		t.Fatalf("expected 1 proxy, got %d", len(conf.Proxies))
	}
	p := conf.Proxies[0]
	if p.GetUsername() != "nested_user" {
		t.Errorf("username = %q, want nested_user", p.GetUsername())
	}
	if p.GetPassword() != "nested_pass" {
		t.Errorf("password = %q, want nested_pass", p.GetPassword())
	}
	if p.Name != "SPB" {
		t.Errorf("name = %q, want SPB", p.Name)
	}
}

func TestParseConfigRoutes(t *testing.T) {
	yaml := `
version: "1"
routes:
  - proxy: 127.0.0.1:58580
    use: true
    exclude:
      - "*.microsoft.com"
    auth:
      username: route_user
      password: route_pass
    rules:
      "SPB":
        priority: 1
      "US":
        priority: 2
proxies:
  - name: SPB
    proxy: 127.0.0.1:6969
    protocol: socks5
    use: true
    exclude:
      - "*.yandex.ru"
  - name: US
    proxy: 127.0.0.1:6066
    protocol: socks5
    use: true
    only:
      - "*.github.com"
`
	conf, err := parseConfigFromString(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(conf.Routes))
	}
	if len(conf.Proxies) != 2 {
		t.Fatalf("expected 2 proxies, got %d", len(conf.Proxies))
	}

	r := conf.Routes[0]
	if r.Dialer != "127.0.0.1:58580" {
		t.Errorf("route dialer = %q, want 127.0.0.1:58580", r.Dialer)
	}
	if len(r.Exclude) != 1 || r.Exclude[0] != "*.microsoft.com" {
		t.Errorf("route exclude = %v, want [*.microsoft.com]", r.Exclude)
	}
	if r.Auth == nil || r.Auth.Username != "route_user" {
		t.Errorf("route auth = %v", r.Auth)
	}
	if len(r.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(r.Rules))
	}
	if r.Rules["SPB"].GetPriority() != 1 {
		t.Errorf("SPB priority = %d, want 1", r.Rules["SPB"].GetPriority())
	}
	if r.Rules["US"].GetPriority() != 2 {
		t.Errorf("US priority = %d, want 2", r.Rules["US"].GetPriority())
	}
}

func TestParseConfigPrirityTypo(t *testing.T) {
	yaml := `
version: "1"
routes:
  - proxy: 127.0.0.1:58580
    use: true
    rules:
      "SPB":
        pririty: 42
`
	conf, err := parseConfigFromString(yaml)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(conf.Routes))
	}
	r := conf.Routes[0]
	if r.Rules["SPB"].GetPriority() != 42 {
		t.Errorf("pririty = %d, want 42", r.Rules["SPB"].GetPriority())
	}
}

func TestParseConfigBothPriorityFields(t *testing.T) {
	// priority has precedence over pririty
	yaml := `
version: "1"
routes:
  - proxy: 127.0.0.1:58580
    use: true
    rules:
      "SPB":
        priority: 10
        pririty: 20
`
	conf, err := parseConfigFromString(yaml)
	if err != nil {
		t.Fatal(err)
	}
	r := conf.Routes[0]
	if r.Rules["SPB"].GetPriority() != 10 {
		t.Errorf("priority should be 10 (priority > pririty), got %d", r.Rules["SPB"].GetPriority())
	}
}

// parseConfigFromString парсит YAML из строки (для тестов).
func parseConfigFromString(data string) (Config, error) {
	tmp, err := os.CreateTemp("", "proxydialer-test-*.yaml")
	if err != nil {
		return Config{}, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(data); err != nil {
		tmp.Close()
		return Config{}, err
	}
	tmp.Close()
	return parseConfig(tmp.Name())
}

// --------------- RouteRule.GetPriority ---------------

func TestRouteRuleGetPriority(t *testing.T) {
	tests := []struct {
		name string
		rule RouteRule
		want int
	}{
		{"priority only", RouteRule{Priority: 5}, 5},
		{"pririty only", RouteRule{Pririty: 7}, 7},
		{"both set", RouteRule{Priority: 10, Pririty: 8}, 10},
		{"zero value", RouteRule{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.rule.GetPriority()
			if got != tt.want {
				t.Errorf("GetPriority = %d, want %d", got, tt.want)
			}
		})
	}
}

// --------------- route with only and exclude on same proxy ---------------

func TestRouteRequestProxyWithBothOnlyExclude(t *testing.T) {
	proxyDialer := testDialer{name: "proxy"}
	// Прокси: *.openai.com в only, но mail.openai.com в exclude
	proxyMap := map[string]NamedProxy{
		"proxy": {Entry: ProxyEntry{
			Name:    "proxy",
			Only:    []string{"*.openai.com"},
			Exclude: []string{"mail.openai.com"},
		}, Dialer: proxyDialer},
	}

	route := RouteEntry{
		Rules: map[string]RouteRule{
			"proxy": {Priority: 1},
		},
	}

	// api.openai.com — в only и не в exclude → проходит
	d, reason := routeRequest("api.openai.com", route, proxyMap)
	if d == proxy.Direct {
		t.Error("api.openai.com should route through proxy")
	}
	if !strings.HasPrefix(reason, "route-only:") {
		t.Errorf("reason = %q, want prefix route-only:", reason)
	}

	// mail.openai.com — в only и в exclude → Direct
	d, reason = routeRequest("mail.openai.com", route, proxyMap)
	if d != proxy.Direct {
		t.Error("mail.openai.com should be direct (only+exclude)")
	}
	if !strings.HasPrefix(reason, "route-no-match") {
		t.Errorf("reason = %q, want prefix route-no-match (no proxy matches)", reason)
	}
}

// --------------- route with missing proxy in rules ---------------

func TestRouteRequestMissingProxy(t *testing.T) {
	spbDialer := testDialer{name: "spb"}
	proxyMap := map[string]NamedProxy{
		"SPB": {Entry: ProxyEntry{Name: "SPB"}, Dialer: spbDialer},
	}

	// Правило ссылается на несуществующий прокси "GHOST"
	route := RouteEntry{
		Rules: map[string]RouteRule{
			"GHOST": {Priority: 1},
			"SPB":   {Priority: 2},
		},
	}

	d, reason := routeRequest("example.com", route, proxyMap)
	if !strings.HasPrefix(reason, "route-default:") {
		t.Errorf("reason = %q, want route-default (missing proxy skipped, SPB used)", reason)
	}
	td, ok := d.(testDialer)
	if !ok || td.name != "spb" {
		t.Errorf("expected spb dialer after skipping missing proxy, got %v", d)
	}
}

// --------------- disabled proxy in route rules ---------------

func TestRouteRequestDisabledProxyInMap(t *testing.T) {
	// Прокси нет в proxyMap (не попал из-за ошибки buildDialer или выключен)
	route := RouteEntry{
		Rules: map[string]RouteRule{
			"SPB": {Priority: 1},
		},
	}

	d, reason := routeRequest("example.com", route, nil)
	if d != proxy.Direct {
		t.Error("expected Direct when proxyMap is nil")
	}
	if !strings.HasPrefix(reason, "route-no-match") {
		t.Errorf("reason = %q, want route-no-match", reason)
	}

	d, reason = routeRequest("example.com", route, map[string]NamedProxy{})
	if d != proxy.Direct {
		t.Error("expected Direct when proxyMap is empty")
	}
	if !strings.HasPrefix(reason, "route-no-match") {
		t.Errorf("reason = %q, want route-no-match", reason)
	}
}
