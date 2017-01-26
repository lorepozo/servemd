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
	"fmt"
	"io/ioutil"
	"log"
	"mime"
	"os"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/valyala/fasthttp"
)

const logf = "[%s %s] %d: %s"

const defaultTpl = `<!doctype html><html>
<head><meta http-equiv="content-type" content="text/html; charset=utf-8"></head>
<body>{{ .Content }}</body>
</html>`

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

func handlerInternalError(err error) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		ctx.Response.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.Response.SetBodyString(err.Error())
		log.Printf(logf, ctx.Method(), ctx.Path(), fasthttp.StatusInternalServerError, err.Error())
	}
}

func handlerLiteralFile(pathStr string) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		mimeType := mime.TypeByExtension(path.Ext(pathStr))
		if mimeType != "" {
			ctx.Response.Header.Set("Content-Type", mimeType)
		}
		ctx.SendFile(pathStr)
		log.Printf(logf, ctx.Method(), ctx.Path(), fasthttp.StatusOK, "literal "+pathStr)
	}
}

func handlerNotFound() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		ctx.Response.SetStatusCode(fasthttp.StatusNotFound)
		ctx.Response.SetBodyString("Not Found")
		log.Printf(logf, ctx.Method(), ctx.Path(), fasthttp.StatusNotFound, "Not Found")
	}
}

func handlerReader(ident string, rd *bytes.Reader) fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		rd.Seek(0, 0)
		rd.WriteTo(ctx)
		ctx.Response.Header.Set("Content-Type", "text/html; charset=utf-8")
		log.Printf(logf, ctx.Method(), ctx.Path(), fasthttp.StatusOK, ident)
	}
}

func handlerRedirect(url string) fasthttp.RequestHandler {
	url = strings.TrimSpace(url)
	return func(ctx *fasthttp.RequestCtx) {
		ctx.Response.SetStatusCode(fasthttp.StatusPermanentRedirect)
		ctx.Response.Header.Set("Location", url)
		log.Printf(logf, ctx.Method(), ctx.Path(), fasthttp.StatusPermanentRedirect, "")
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
func (st settings) toServer() *server {
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
	if err == nil {
		_, err = s.mdTemplate.Parse(string(tpl))
	}
	if err != nil {
		// couldn't parse template
		s.mdTemplate.Parse(defaultTpl)
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
		fallthrough
	case "none":
		s.tls.required = requiredNone
	case "secrets":
		s.tls.required = requiredSecrets
	case "all":
		s.tls.required = requiredAll
	default:
		fmt.Fprintln(os.Stderr, "bad 'tls.required' field")
		os.Exit(1)
	}
	return s
}
