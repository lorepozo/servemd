/*
Copyright (C) 2016  Lucas Morales <lucas@lucasem.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"
)

const logf = "[%s %s] %d: %s"

type templateContent struct {
	Content string
}

// parseHeader parses comma-separated key=value pairs into a map.
func parseHeader(s string) map[string]string {
	result := make(map[string]string)
	for _, kv := range strings.Split(s, ",") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) != 2 {
			continue
		}
		result[strings.Trim(parts[0], `" `)] = strings.Trim(parts[1], `" `)
	}
	return result
}

const (
	requiredNone = iota
	requiredSecrets
	requiredAll
)

func handlerInternalError(err error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf(logf, r.Method, r.URL.Path, http.StatusInternalServerError, err.Error())
	}
}

func handlerLiteralFile(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path)
		log.Printf(logf, r.Method, r.URL.Path, http.StatusOK, "literal "+path)
	}
}

func handlerNotFound() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
		log.Printf(logf, r.Method, r.URL.Path, http.StatusNotFound, "")
	}
}

func handlerReader(ident string, rd *bytes.Reader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rd.Seek(0, 0)
		rd.WriteTo(w)
		log.Printf(logf, r.Method, r.URL.Path, http.StatusOK, ident)
	}
}

// settings is unmarshalled from a yaml file according to this
// specification.
type settings struct {
	Host     string            // optional, defaults to kernal-reported hostname
	Dir      string            // optional, defaults to directory of settings file
	Port     string            // optional, defaults to '80'
	Template string            // required
	Log      string            // optional, defaults to stdout
	Secrets  map[string]string // optional
	TTL      int               // optional, defaults to '0' minutes
	TLS      struct {          // optional
		Only     bool   // optional
		Required string // optional, 'all' or 'secrets'
		Port     string // optional, defaults to '443'
		Cert     string // required for TLS
		Privkey  string // required for TLS
	} `yaml:"tls"`
}

// toServer creates a server from the settings struct. The server host is
// determined using the host name reported by the kernel.
func (st settings) toServer(logFile io.Writer) *server {
	s := new(server)
	s.path = st.Dir
	if !st.TLS.Only {
		s.port = st.Port
		if s.port == "" {
			s.port = "80"
		}
	}
	s.host = st.Host
	if s.host == "" {
		if host, err := os.Hostname(); err == nil {
			s.host = host
		} else {
			s.host = "localhost"
		}
	}
	s.mdTemplate = template.New("tpl")
	tpl, err := ioutil.ReadFile(st.Template)
	if err != nil {
		// couldn't load template
		os.Exit(4)
	}
	_, err = s.mdTemplate.Parse(string(tpl))
	if err != nil {
		// couldn't parse template
		os.Exit(5)
	}
	s.secret = st.Secrets

	if st.TTL != 0 {
		var t time.Duration
		if st.TTL > 0 {
			t = time.Minute * time.Duration(st.TTL)
		} else {
			t = -1
		}
		s.ttl = &t
	}

	doTLS := st.TLS.Cert != "" && st.TLS.Privkey != ""
	if !doTLS {
		return s
	}
	s.tls.port = st.TLS.Port
	if s.tls.port == "" {
		s.tls.port = "443"
	}
	s.tls.cert = st.TLS.Cert
	s.tls.key = st.TLS.Privkey
	switch st.TLS.Required {
	case "":
		s.tls.required = requiredNone
	case "secrets":
		s.tls.required = requiredSecrets
	case "all":
		s.tls.required = requiredAll
	default:
		// bad 'tls.required' field
		os.Exit(6)
	}
	return s
}
