// Package fakeapi provides a loopback-only InSpace API double for contract and
// smoke tests. It never proxies or falls through to another endpoint.
package fakeapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"sync"

	"github.com/thanet-s/inspace-cloud-kube-modules/cloud-provider-inspace/pkg/inspace"
)

const VMUUID = "aaaaaaaa-1111-4222-8333-bbbbbbbbbbbb"

type Server struct {
	server *httptest.Server
	apiKey string

	mu  sync.Mutex
	vms map[string]inspace.VM
}

func New(apiKey string) *Server {
	s := &Server{apiKey: apiKey, vms: make(map[string]inspace.VM)}
	s.server = httptest.NewServer(http.HandlerFunc(s.serveHTTP))
	return s
}

func (s *Server) URL() string { return s.server.URL }
func (s *Server) Close()      { s.server.Close() }

func (s *Server) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("apikey") != s.apiKey {
		writeError(w, http.StatusUnauthorized, "invalid API key")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/config/locations":
		writeJSON(w, http.StatusOK, []inspace.Location{{DisplayName: "Bangkok", Slug: "bkk01", CountryCode: "tha", IsDefault: true}})
	case r.Method == http.MethodGet && r.URL.Path == "/v1/bkk01/user-resource/host_pool/list":
		writeJSON(w, http.StatusOK, []inspace.HostPool{{UUID: "aac7dd66-f390-4edd-80c0-dd7cae49bd99", Name: "Intel Scalable", IsDefaultDesignated: true}})
	case r.URL.Path == "/v1/bkk01/user-resource/vm/list" && r.Method == http.MethodGet:
		s.listVMs(w)
	case r.URL.Path == "/v1/bkk01/user-resource/vm":
		s.vm(w, r)
	default:
		writeError(w, http.StatusNotFound, "route not implemented by fake")
	}
}

func (s *Server) listVMs(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]inspace.VM, 0, len(s.vms))
	for _, vm := range s.vms {
		result = append(result, vm)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].UUID < result[j].UUID })
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) vm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// net/http intentionally parses form bodies only for POST, PUT, and PATCH.
	// The Warren-compatible API uses form bodies on DELETE as well.
	if r.Method == http.MethodDelete {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		values, err := url.ParseQuery(string(body))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		for key, items := range values {
			r.Form[key] = append(r.Form[key], items...)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch r.Method {
	case http.MethodPost:
		vcpu, _ := strconv.Atoi(r.Form.Get("vcpu"))
		memory, _ := strconv.Atoi(r.Form.Get("ram"))
		disk, _ := strconv.Atoi(r.Form.Get("disks"))
		if r.Form.Get("name") == "" || vcpu == 0 || memory == 0 || disk == 0 {
			writeError(w, http.StatusUnprocessableEntity, "missing VM fields")
			return
		}
		vm := inspace.VM{
			UUID:               VMUUID,
			Name:               r.Form.Get("name"),
			Status:             "running",
			VCPU:               vcpu,
			MemoryMiB:          memory,
			OSName:             r.Form.Get("os_name"),
			OSVersion:          r.Form.Get("os_version"),
			PrivateIPv4:        "10.0.0.10",
			DesignatedPoolUUID: r.Form.Get("designated_pool_uuid"),
			Storage:            []inspace.VMStorage{{UUID: "cccccccc-1111-4222-8333-dddddddddddd", Name: "vda", SizeGiB: disk, Primary: true}},
		}
		s.vms[vm.UUID] = vm
		writeJSON(w, http.StatusCreated, vm)
	case http.MethodGet:
		vm, ok := s.vms[r.URL.Query().Get("uuid")]
		if !ok {
			writeError(w, http.StatusNotFound, "VM not found")
			return
		}
		writeJSON(w, http.StatusOK, vm)
	case http.MethodDelete:
		uuid := r.Form.Get("uuid")
		if _, ok := s.vms[uuid]; !ok {
			writeError(w, http.StatusNotFound, "VM not found")
			return
		}
		delete(s.vms, uuid)
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{"errors": map[string]string{"Error": message}})
}
