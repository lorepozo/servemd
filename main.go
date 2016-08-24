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
	"crypto/md5"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	fp "path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/Joker/jade"
	"github.com/patrickmn/go-cache"
	"github.com/russross/blackfriday"
	"gopkg.in/yaml.v2"
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
	RequiredNone = iota
	RequiredSecrets
	RequiredAll
)

func handlerNotFound() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
		log.Printf(logf, r.Method, r.URL.Path, http.StatusNotFound, "")
	}
}

func handlerInternalError(err error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Printf(logf, r.Method, r.URL.Path, http.StatusInternalServerError, err.Error())
	}
}

func handlerLiteralFile(path string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, path)
		log.Printf(logf, r.Method, r.URL.Path, http.StatusOK, "serving "+path)
	}
}

type server struct {
	// Path is the absolute path to the directory being served.
	Path string

	// Port is the port on which the server is being hosted.
	Port string

	// Host is the hostname of the server.
	Host string

	// Secret maps secured routes to their corresponding passwords.
	Secret map[string]string

	// MdTemplate for HTML generated from Markdown.
	MdTemplate *template.Template

	// TTL is the time-to-live for the cache. If nil, no caching is done.
	TTL   *time.Duration
	cache *cache.Cache

	// TLS maintains information for a supplementary TLS server.
	TLS struct {
		// Port is the port on which the TLS server is being hosted.
		Port string

		// Required specifies the necessity of TLS to view resources.
		Required int

		// cert is the file name of the certificate for the server.
		cert string

		// key is the file name of the private key for the server.
		key string
	}
}

// checkAuth validates a request for proper authentication, given that the
// route requires it (i.e. the route is a key in s.Secret).
func (s *server) checkAuth(req *http.Request, route string) bool {
	h := strings.SplitN(req.Header.Get("Authorization"), " ", 2)
	if len(h) != 2 || h[0] != "Digest" {
		return false
	}
	digest := parseHeader(h[1])
	realm := s.Host + `-` + route
	if digest["realm"] != realm {
		return false
	}
	nonce := digest["nonce"]
	nc := digest["nc"]
	cnonce := digest["cnonce"]
	qop := digest["qop"]
	ha1b := md5.Sum([]byte(digest["username"] + ":" + realm + ":" + s.Secret[route]))
	ha2b := md5.Sum([]byte(req.Method + ":" + req.URL.Path))
	ha1 := fmt.Sprintf("%x", ha1b)
	ha2 := fmt.Sprintf("%x", ha2b)
	sd := strings.Join([]string{ha1, nonce, nc, cnonce, qop, ha2}, ":")
	resb := md5.Sum([]byte(sd))
	res := fmt.Sprintf("%x", resb)
	return res == digest["response"]
}

// sendChallenge sends an authentication request according to the Digest
// Access Authentication scheme per RFC 2617 using the WWW-Authenticate
// header.
func (s *server) sendChallenge(w http.ResponseWriter, req *http.Request, route string) {
	realm := fmt.Sprintf(`realm="%s-%s"`, s.Host, route)
	qop := `qop="auth,auth-int"`
	nonce := fmt.Sprintf(`nonce="%x"`, time.Now())
	challenge := strings.Join([]string{realm, qop, nonce}, ", ")
	w.Header().Set("WWW-Authenticate", "Digest "+challenge)
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
	log.Printf(logf, req.Method, req.URL.Path, http.StatusUnauthorized, "challenge sent")
}

// serve runs the http server on the specified port.
func (s *server) serve() {
	if s.TTL != nil {
		s.cache = cache.New(*s.TTL, time.Minute)
		s.cache.OnEvicted(func(key string, _ interface{}) {
			log.Printf("removed cached item for %s", key)
		})
	}
	if s.TLS.Port != "" {
		go func() {
			log.Printf("starting HTTPS server on port %s", s.TLS.Port)
			log.Fatal(http.ListenAndServeTLS(":"+s.TLS.Port, s.TLS.cert, s.TLS.key, s))
		}()
	}
	if s.Port != "" {
		go func() {
			log.Printf("starting HTTP server on port %s", s.Port)
			log.Fatal(http.ListenAndServe(":"+s.Port, s))
		}()
	}
	// wait forever
	<-make(chan struct{})
}

func (s *server) serveFilteredFile(w http.ResponseWriter, req *http.Request, filename string) {
	var h http.HandlerFunc
	defer func() {
		if s.cache != nil {
			s.cache.Set(req.URL.Path, h, cache.DefaultExpiration)
		}
		h(w, req)
	}()
	switch {
	case strings.HasSuffix(filename, ".md"):
		md, err := ioutil.ReadFile(filename)
		if err != nil {
			h = handlerInternalError(err)
			return
		}
		out := blackfriday.MarkdownCommon(md)
		content := &templateContent{string(out)}
		h = func(w http.ResponseWriter, r *http.Request) {
			s.MdTemplate.Execute(w, content)
			log.Printf(logf, r.Method, r.URL.Path, http.StatusOK, "markdown "+filename)
		}
	case strings.HasSuffix(filename, ".jade"):
		out, err := jade.ParseFile(filename)
		if err != nil {
			h = handlerInternalError(err)
			return
		}
		h = func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, out)
			log.Printf(logf, r.Method, r.URL.Path, http.StatusOK, "jade "+filename)
		}
	default:
		h = handlerLiteralFile(filename)
	}
}

// ServeHTTP handles requests. It first authenticates using Digest Access
// Authentication if necessary. Literal matches to the path are served
// first, followed by files matching an implicit extension, and finally
// a directory index if applicable.
func (s *server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if s.TLS.Port != "" {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000")
	}
	if s.checkTLSRedirect(w, req, RequiredAll) {
		return
	}

	if len(req.URL.Path) > 1 {
		splits := strings.Split(req.URL.Path, "/")
		if len(splits) > 1 {
			route := splits[1]
			_, isSecret := s.Secret[route]
			if isSecret {
				if s.checkTLSRedirect(w, req, RequiredSecrets) {
					return
				}
				ok := s.checkAuth(req, route)
				if !ok {
					s.sendChallenge(w, req, route)
					return
				}
			}
		}
	}

	if s.cache != nil {
		h, ok := s.cache.Get(req.URL.Path)
		if ok {
			log.Printf("found in cache: %s", req.URL.Path)
			h.(http.HandlerFunc)(w, req)
			return
		}
	}

	path := fp.Join(s.Path, req.URL.Path)
	fi, err := os.Stat(path)
	if err == nil {
		if !fi.IsDir() {
			// literal file exists
			h := handlerLiteralFile(path)
			if s.cache != nil {
				s.cache.Set(req.URL.Path, h, cache.DefaultExpiration)
			}
			h(w, req)
			return
		}
	}

	files, err := ioutil.ReadDir(fp.Dir(path))
	if err != nil {
		h := handlerNotFound()
		if s.cache != nil {
			s.cache.Set(req.URL.Path, h, cache.DefaultExpiration)
		}
		h(w, req)
		return
	}

	// find first file matching name.*
	filtered := ""
	name := fp.Base(path)
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		ext := fp.Ext(file.Name())
		pref := strings.TrimSuffix(file.Name(), ext)
		if pref == name {
			filtered = file.Name()
			break
		}
	}
	if filtered != "" {
		// matching file found
		filename := fp.Join(fp.Dir(path), filtered)
		s.serveFilteredFile(w, req, filename)
		return
	}

	fi, err = os.Stat(path)
	if err != nil {
		h := handlerNotFound()
		if s.cache != nil {
			s.cache.Set(req.URL.Path, h, cache.DefaultExpiration)
		}
		h(w, req)
		return
	}

	// directory requested, force trailing "/"
	if !strings.HasSuffix(req.URL.Path, "/") {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, r.URL.Path+"/", http.StatusMovedPermanently)
			log.Printf(logf, r.Method, r.URL.Path, http.StatusMovedPermanently, "")
		})
		if s.cache != nil {
			s.cache.Set(req.URL.Path, h, cache.DefaultExpiration)
		}
		h(w, req)
		return
	}

	// serve directory index
	files, _ = ioutil.ReadDir(path)
	// find first file matching index.*
	filtered = ""
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		ext := fp.Ext(file.Name())
		pref := strings.TrimSuffix(file.Name(), ext)
		if pref == "index" {
			filtered = file.Name()
			break
		}
	}
	if filtered != "" {
		// matching file found
		filename := fp.Join(path, filtered)
		s.serveFilteredFile(w, req, filename)
		return
	}

	h := handlerNotFound()
	if s.cache != nil {
		s.cache.Set(req.URL.Path, h, cache.DefaultExpiration)
	}
	h(w, req)
}

func (s *server) checkTLSRedirect(w http.ResponseWriter, req *http.Request, cond int) bool {
	if s.TLS.Required != cond || req.TLS != nil {
		return false
	}
	http.Redirect(w, req, fmt.Sprintf("https://%s%s", s.Host, req.URL.Path), http.StatusSeeOther)
	return true
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
	s.Path = st.Dir
	if !st.TLS.Only {
		s.Port = st.Port
		if s.Port == "" {
			s.Port = "80"
		}
	}
	s.Host = st.Host
	if s.Host == "" {
		if host, err := os.Hostname(); err == nil {
			s.Host = host
		} else {
			s.Host = "localhost"
		}
	}
	s.MdTemplate = template.New("tpl")
	tpl, err := ioutil.ReadFile(st.Template)
	if err != nil {
		// couldn't load template
		os.Exit(4)
	}
	_, err = s.MdTemplate.Parse(string(tpl))
	if err != nil {
		// couldn't parse template
		os.Exit(5)
	}
	s.Secret = st.Secrets

	if st.TTL != 0 {
		var t time.Duration
		if st.TTL > 0 {
			t = time.Minute * time.Duration(st.TTL)
		} else {
			t = -1
		}
		s.TTL = &t
	}

	doTLS := st.TLS.Cert != "" && st.TLS.Privkey != ""
	if !doTLS {
		return s
	}
	s.TLS.Port = st.TLS.Port
	if s.TLS.Port == "" {
		s.TLS.Port = "443"
	}
	s.TLS.cert = st.TLS.Cert
	s.TLS.key = st.TLS.Privkey
	switch st.TLS.Required {
	case "":
		s.TLS.Required = RequiredNone
	case "secrets":
		s.TLS.Required = RequiredSecrets
	case "all":
		s.TLS.Required = RequiredAll
	default:
		// bad 'TLS.Required' field
		os.Exit(6)
	}
	return s
}

func main() {
	if len(os.Args) < 2 {
		// no settings file supplied
		os.Exit(1)
	}
	set := os.Args[1]
	stu, err := ioutil.ReadFile(set)
	if err != nil {
		// couldn't open settings file
		os.Exit(2)
	}
	st := settings{}
	err = yaml.Unmarshal(stu, &st)
	if err != nil {
		// couldn't parse settings file
		os.Exit(3)
	}
	stpath, _ := fp.Abs(fp.Dir(set))
	if !fp.IsAbs(st.Dir) {
		st.Dir = fp.Join(stpath, st.Dir)
	}
	if !fp.IsAbs(st.Template) {
		st.Template = fp.Join(stpath, st.Template)
	}
	if st.Log != "" && !fp.IsAbs(st.Log) {
		st.Log = fp.Join(stpath, st.Log)
	}
	if st.TLS.Cert != "" && !fp.IsAbs(st.TLS.Cert) {
		st.TLS.Cert = fp.Join(stpath, st.TLS.Cert)
	}
	if st.TLS.Privkey != "" && !fp.IsAbs(st.TLS.Privkey) {
		st.TLS.Privkey = fp.Join(stpath, st.TLS.Privkey)
	}

	logFile := os.Stderr
	if st.Log != "" {
		f, err := os.OpenFile(st.Log, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err == nil {
			defer f.Close()
			logFile = f
		}
	}
	log.SetOutput(logFile)
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	st.toServer(logFile).serve()
}
