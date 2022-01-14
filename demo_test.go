package SiriusGeo_test

import (
	"context"
	"github.com/bay1ts/SiriusGeo"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDemo(t *testing.T) {
	cfg := SiriusGeo.CreateConfig()
	cfg.DatabaseFilePath = "D:\\Develop\\IP2LOCATION-LITE-DB1.BIN\\IP2LOCATION-LITE-DB1.BIN"
	cfg.AllowedCountries = []string{"US"}
	cfg.ModSecurityUrl = "aa"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := SiriusGeo.New(ctx, next, cfg, "vvv")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Real-IP", "101.24.203.243")
	handler.ServeHTTP(recorder, req)
	resp := recorder.Result()
	defer resp.Body.Close()
	log.Printf("response -- %v", resp.Body)
	assertHeader(t, req, "X-Host", "localhost")
	assertHeader(t, req, "X-URL", "http://localhost")
	assertHeader(t, req, "X-Method", "GET")
	assertHeader(t, req, "X-Demo", "test")
}

func assertHeader(t *testing.T, req *http.Request, key, expected string) {
	t.Helper()

	if req.Header.Get(key) != expected {
		t.Errorf("invalid header value: %s", req.Header.Get(key))
	}
}
