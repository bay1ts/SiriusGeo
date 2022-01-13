package SiriusGeo

import (
	"context"
	"fmt"

	"github.com/ip2location/ip2location-go/v9"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

type Config struct {
	DatabaseFilePath     string   // Path to ip2location database file
	AllowedCountries     []string // Whitelist of countries to allow (ISO 3166-1 alpha-2)
	AllowedIP            []string // Whitelist of ip to allow
	AllowPrivate         bool     // Allow requests from private / internal networks?
	DisallowedStatusCode int      // HTTP status code to return for disallowed requests
}

func CreateConfig() *Config {
	return &Config{
		DatabaseFilePath:     "/dd/IP2LOCATION-LITE-DB1.BIN",
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
	allowedCountries     []string
	allowedIps           []string
	allowPrivate         bool
	disallowedStatusCode int
	privateIPRanges      []*net.IPNet
}

func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	if _, err := os.Stat(cfg.DatabaseFilePath); err != nil {
		log.Printf("[geoip2] DB `%s' not found: %v", cfg.DatabaseFilePath, err)
		return &Plugin{
			next: next,
			name: name,
		}, nil
	}

	db, err := ip2location.OpenDB(cfg.DatabaseFilePath)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to open database: %w", name, err)
	}

	return &Plugin{
		db:                   db,
		next:                 next,
		name:                 name,
		allowedCountries:     cfg.AllowedCountries,
		allowedIps:           cfg.AllowedIP,
		allowPrivate:         cfg.AllowPrivate,
		disallowedStatusCode: cfg.DisallowedStatusCode,
		privateIPRanges:      InitPrivateIPBlocks(),
	}, nil
}
func (p Plugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if p.db == nil {
		p.next.ServeHTTP(rw, req)
		return
	}
	for _, ip := range p.GetRemoteIPs(req) {
		if !p.CheckAllowed(ip) {
			log.Printf("%s: %v", p.name, "禁止访问")
			rw.WriteHeader(p.disallowedStatusCode)
			rw.Write([]byte("禁止访问"))
		}
	}
	p.next.ServeHTTP(rw, req)
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
		log.Printf("此次请求获取到ip------%v", ip)
		ips = append(ips, ip)
	}

	log.Printf("此次请求获取到ip数量------%v", len(ips))
	return ips
}
func (p Plugin) CheckAllowed(ip string) bool {
	if p.isAllowIP(ip) || p.isAllowArea(ip) {
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
			if countryCode == "-" {
				if p.allowPrivate {
					return true
				}
			}
			log.Printf("%s: %s belongs to %v", p.name, ip, countryCode)
			for i := 0; i < len(p.allowedCountries); i++ {
				if p.allowedCountries[i] == countryCode {
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
