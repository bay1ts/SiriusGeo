package SiriusGeo

import (
	"bytes"
	"context"
	"fmt"
	"github.com/bluele/gcache"
	"github.com/ip2location/ip2location-go/v9"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var httpClient = &http.Client{
	Timeout: time.Second * 2,
}

type Config struct {
	DatabaseFilePath     string   // Path to ip2location database file
	AllowedCountries     []string // Whitelist of countries to allow (ISO 3166-1 alpha-2)
	AllowedIP            []string // Whitelist of ip to allow
	AllowPrivate         bool     // Allow requests from private / internal networks?
	DisallowedStatusCode int      // HTTP status code to return for disallowed requests
	ModSecurityUrl       string
}

func CreateConfig() *Config {
	return &Config{
		//DatabaseFilePath:     "/db/IP2LOCATION-LITE-DB1.BIN",
		AllowedCountries:     []string{},
		AllowedIP:            []string{},
		AllowPrivate:         true,
		DisallowedStatusCode: http.StatusForbidden,
	}
}

type Plugin struct {
	next                 http.Handler
	name                 string
	db                   *ip2location.DB
	wafCache             gcache.Cache
	geoCache             gcache.Cache
	modSecurityUrl       string
	allowedCountries     []string
	allowedIps           []string
	allowPrivate         bool
	disallowedStatusCode int
	privateIPRanges      []*net.IPNet
	counter              *int
}

func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	if _, err := os.Stat(cfg.DatabaseFilePath); err != nil {
		log.Printf("[ip2location] DB `%s' not found: %v", cfg.DatabaseFilePath, err)
		return &Plugin{
			next: next,
			name: name,
		}, nil
	}
	if len(cfg.ModSecurityUrl) == 0 {
		return nil, fmt.Errorf("modSecurityUrl cannot be empty")
	}
	db, err := ip2location.OpenDB(cfg.DatabaseFilePath)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to open database: %w", name, err)
	}

	wafCache := gcache.New(2048).LRU().Build()
	geoCache := gcache.New(10240).LRU().Expiration(time.Minute * 30).Build()
	c := 0
	return &Plugin{
		db:                   db,
		next:                 next,
		name:                 name,
		allowedCountries:     cfg.AllowedCountries,
		allowedIps:           cfg.AllowedIP,
		allowPrivate:         cfg.AllowPrivate,
		disallowedStatusCode: cfg.DisallowedStatusCode,
		modSecurityUrl:       cfg.ModSecurityUrl,
		privateIPRanges:      InitPrivateIPBlocks(),
		wafCache:             wafCache,
		geoCache:             geoCache,
		counter:              &c,
	}, nil
}
func (p Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if isWebsocket(req) {
		p.next.ServeHTTP(rw, req)
		return
	}
	if p.db == nil {
		p.next.ServeHTTP(rw, req)
		return
	}
	*p.counter += 1
	log.Printf("%s: access count %v", p.name, *p.counter)
	if *p.counter >= 5 {
		*p.counter = 0
		log.Printf("%s: geoCache hit rate= %v,wafCache hit rate= %v", p.name, p.geoCache.HitRate(), p.wafCache.HitRate())
	}
	for _, ip := range p.GetRemoteIPs(req) {
		if _, notFound := p.wafCache.GetIFPresent(ip); notFound == nil || !p.CheckAllowed(ip) {
			//if p.wafCache.Has(ip) || !p.CheckAllowed(ip) {
			log.Printf("%s: %v access denied", p.name, ip)
			rw.WriteHeader(p.disallowedStatusCode)
			rw.Header().Set("Content-Type", "text/html; charset=utf-8")
			rw.Write([]byte(fmt.Sprintf("<h1>Your IP [%s] is denied to access</h1>", ip)))
			return
		} else {
			go p.CallWaf(ip, rw, req)
		}
	}
	p.next.ServeHTTP(rw, req)
}
func (p Plugin) CallWaf(ip string, rw http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Body = ioutil.NopCloser(bytes.NewReader(body))
	url := fmt.Sprintf("%s%s", p.modSecurityUrl, req.RequestURI)
	proxyReq, err := http.NewRequest(req.Method, url, bytes.NewReader(body))

	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	proxyReq.Header = make(http.Header)
	for h, val := range req.Header {
		proxyReq.Header[h] = val
	}
	resp, err := httpClient.Do(proxyReq)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		//block
		log.Printf("%s: %v 触发防火墙", p.name, ip)
		//cache[ip] = struct{}{}
		p.wafCache.SetWithExpire(ip, nil, time.Minute*30)
		return
	}
}
func (p Plugin) GetRemoteIPs(req *http.Request) []string {
	uniqIPs := make(map[string]struct{})

	if xff := req.Header.Get("x-forwarded-for"); xff != "" {
		for _, ip := range strings.Split(xff, ",") {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			uniqIPs[ip] = struct{}{}
		}
	}
	if xri := req.Header.Get("x-real-ip"); xri != "" {
		for _, ip := range strings.Split(xri, ",") {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			uniqIPs[ip] = struct{}{}
		}
	}

	var ips []string
	for ip := range uniqIPs {
		ips = append(ips, ip)
	}

	return ips
}
func (p Plugin) CheckAllowed(ip string) bool {
	if _, notFound := p.geoCache.GetIFPresent(ip); notFound == nil || p.isAllowIP(ip) || p.isAllowArea(ip) {
		return true
	} else {
		return false
	}
}
func (p Plugin) isAllowIP(ip string) bool {
	ipAddress := net.ParseIP(ip)
	isPrivateIp := p.IsPrivateIP(ipAddress, p.privateIPRanges)

	if isPrivateIp && p.allowPrivate {
		return true
	} else if isPrivateIp && !p.allowPrivate {

	} else {
		if len(p.allowedIps) > 0 {
			for _, allowedIp := range p.allowedIps {
				if strings.Contains(allowedIp, "/") {
					_, ipv4Net, err := net.ParseCIDR(allowedIp)
					if err != nil {
						continue
					}
					if ipv4Net.Contains(net.ParseIP(ip)) {
						return true
					}
				} else {
					allowedIpStr := net.ParseIP(allowedIp)
					if ip == allowedIpStr.String() {
						return true
					}
				}
			}
		}
	}
	return false
}
func (p Plugin) isAllowArea(ip string) bool {
	if len(p.allowedCountries) > 0 {
		if record, err := p.db.Get_country_short(ip); err == nil {
			countryCode := record.Country_short
			log.Printf("%s: %s belongs to %v", p.name, ip, countryCode)
			for i := 0; i < len(p.allowedCountries); i++ {
				if p.allowedCountries[i] == countryCode {
					p.geoCache.Set(ip, nil)
					return true
				}
			}
		}
	}
	return false
}
func (p Plugin) IsPrivateIP(ip net.IP, privateIPBlocks []*net.IPNet) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return true
		}
	}

	return false
}

type NotAllowedError struct {
	Country string
	IP      string
	Reason  string
}

func (e NotAllowedError) Error() (err string) {
	if e.Country == "" {
		err = fmt.Sprintf("%s not allowed", e.IP)
	} else {
		err = fmt.Sprintf("%s (%s) not allowed", e.IP, e.Country)
	}
	if e.Reason != "" {
		err = fmt.Sprintf("%s: %s", err, e.Reason)
	}

	return err
}
func InitPrivateIPBlocks() []*net.IPNet {
	var privateIPBlocks []*net.IPNet

	for _, cidr := range []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 link-local
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local addr
	} {
		_, block, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Errorf("parse error on %q: %v", cidr, err))
		}
		privateIPBlocks = append(privateIPBlocks, block)
	}

	return privateIPBlocks
}
func isWebsocket(req *http.Request) bool {
	for _, header := range req.Header["Upgrade"] {
		if header == "websocket" {
			return true
		}
	}
	return false
}
