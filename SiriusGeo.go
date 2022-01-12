package SiriusGeo

import (
	"context"
	"errors"
	"fmt"
	"github.com/oschwald/geoip2-golang"
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
type Plugin struct {
	next                 http.Handler
	name                 string
	db                   *geoip2.Reader
	enabled              bool
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

	db, err := geoip2.Open(cfg.DatabaseFilePath)
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
		err := p.CheckAllowed(ip)
		if err != nil {
			var notAllowedErr *NotAllowedError
			if errors.As(err, &notAllowedErr) {
				log.Printf("%s: %v", p.name, err)
				rw.WriteHeader(p.disallowedStatusCode)
				return
			} else {
				log.Printf("%s: %s - %v", p.name, req.Host, err)
				rw.WriteHeader(p.disallowedStatusCode)
				return
			}
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
		ips = append(ips, ip)
	}

	return ips
}
func (p Plugin) CheckAllowed(ip string) error {
	ipErr := p.isAllowIP(ip)
	areaErr := p.isAllowArea(ip)

	if areaErr != nil {
		return areaErr
	} else if ipErr != nil {
		return ipErr
	} else {
		return nil
	}
}
func (p Plugin) isAllowIP(ip string) error {
	ipAddress := net.ParseIP(ip)
	isPrivateIp := p.IsPrivateIP(ipAddress, p.privateIPRanges)

	if isPrivateIp && p.allowPrivate {
		return nil
	} else if isPrivateIp && !p.allowPrivate {
		return &NotAllowedError{
			IP:      ip,
			Country: "-",
		}
	}
	if len(p.allowedIps) > 0 {
		for _, allowedIp := range p.allowedIps {
			if strings.Contains(allowedIp, "/") {
				_, ipv4Net, err := net.ParseCIDR(allowedIp)
				if err != nil {
					continue
				}
				if ipv4Net.Contains(net.ParseIP(ip)) {
					return nil
				}
			} else {
				allowedIpStr := net.ParseIP(allowedIp)
				if ip == allowedIpStr.String() {
					return nil
				}
			}
		}
		return &NotAllowedError{
			Country: "-",
			IP:      ip,
		}
	} else {
		return &NotAllowedError{
			Country: "-",
			IP:      "all",
		}
	}
}
func (p Plugin) isAllowArea(ip string) error {
	if len(p.allowedCountries) > 0 {
		//todo
		//defer p.db.Close()
		netIp := net.ParseIP(ip)
		record, err := p.db.City(netIp)
		if err != nil {
			return err
		}
		countryCode := record.Country.IsoCode
		for i := 0; i < len(p.allowedCountries); i++ {
			if p.allowedCountries[i] == countryCode {
				return nil
			}
		}
		return &NotAllowedError{
			Country: countryCode,
			IP:      ip,
		}
	} else {
		return &NotAllowedError{
			Country: "all",
			IP:      ip,
		}
	}
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
