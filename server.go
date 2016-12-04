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
	"crypto/md5"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	fp "path/filepath"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/Joker/jade"
	"github.com/patrickmn/go-cache"
	"github.com/russross/blackfriday"
	"github.com/valyala/fasthttp"
)

type server struct {
	// path is the absolute path to the directory being served.
	path string

	// port is the port on which the server is being hosted.
	port string

	// host is the hostname of the server.
	host string

	// secret maps secured routes to their corresponding passwords.
	secret map[string]string

	// mdTemplate for HTML generated from Markdown.
	mdTemplate *template.Template

	// ttl is the time-to-live for the cache. If nil, no caching is done.
	ttl   *time.Duration
	cache *cache.Cache

	// tls maintains information for a supplementary TLS server.
	tls struct {
		// port is the port on which the TLS server is being hosted.
		port string

		// required specifies the necessity of TLS to view resources.
		required int

		// cert is the file name of the certificate for the server.
		cert string

		// key is the file name of the private key for the server.
		key string
	}
}

func (s *server) initiateCache() {
	s.cache = cache.New(*s.ttl, time.Minute)
	s.cache.OnEvicted(func(key string, _ interface{}) {
		log.Printf("removed cached item for %s", key)
	})
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, os.Signal(syscall.SIGUSR1))
	go func() {
		for {
			<-sc
			s.cache.Flush()
			log.Println("received SIGUSR1, cache has been flushed")
		}
	}()
}

// checkAuth validates a request for proper authentication, given that the
// route requires it (i.e. the route is a key in s.Secret).
func (s *server) checkAuth(ctx *fasthttp.RequestCtx, route string) bool {
	h := strings.SplitN(string(ctx.Request.Header.Peek("Authorization")), " ", 2)
	if len(h) != 2 || h[0] != "Digest" {
		return false
	}
	digest := parseHeader(h[1])
	realm := s.host + `-` + route
	if digest["realm"] != realm {
		return false
	}
	nonce := digest["nonce"]
	nc := digest["nc"]
	cnonce := digest["cnonce"]
	qop := digest["qop"]
	ha1b := md5.Sum([]byte(digest["username"] + ":" + realm + ":" + s.secret[route]))
	ha2b := md5.Sum([]byte(fmt.Sprintf("%s:%s", ctx.Method(), ctx.Path())))
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
func (s *server) sendChallenge(ctx *fasthttp.RequestCtx, route string) {
	realm := fmt.Sprintf(`realm="%s-%s"`, s.host, route)
	qop := `qop="auth,auth-int"`
	nonce := fmt.Sprintf(`nonce="%x"`, time.Now())
	challenge := strings.Join([]string{realm, qop, nonce}, ", ")
	ctx.Response.Header.Set("WWW-Authenticate", "Digest "+challenge)

	ctx.Response.SetStatusCode(fasthttp.StatusUnauthorized)
	ctx.Response.SetBodyString("Unauthorized")
	log.Printf(logf, ctx.Method(), ctx.Path(), fasthttp.StatusUnauthorized, "Unauthorized")
}

// serve runs the http server on the specified port.
func (s *server) serve() {
	if s.ttl != nil {
		s.initiateCache()
	}
	if s.tls.port != "" {
		go func() {
			log.Printf("starting HTTPS server on port %s", s.tls.port)
			log.Fatal(fasthttp.ListenAndServeTLS(":"+s.tls.port, s.tls.cert, s.tls.key, s.ServeHTTP))
		}()
	}
	if s.port != "" {
		go func() {
			log.Printf("starting HTTP server on port %s", s.port)
			log.Fatal(fasthttp.ListenAndServe(":"+s.port, s.ServeHTTP))
		}()
	}
	// wait forever
	<-make(chan struct{})
}

func (s *server) serveFilteredFile(ctx *fasthttp.RequestCtx, filename string) {
	var h fasthttp.RequestHandler
	defer func() {
		if s.cache != nil {
			s.cache.Set(string(ctx.Path()), h, cache.DefaultExpiration)
		}
		h(ctx)
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
		buf := new(bytes.Buffer)
		s.mdTemplate.Execute(buf, content)
		rd := bytes.NewReader(buf.Bytes())
		h = handlerReader("markdown "+filename, rd)
	case strings.HasSuffix(filename, ".jade"):
		fallthrough
	case strings.HasSuffix(filename, ".pug"):
		out, err := jade.ParseFile(filename)
		if err != nil {
			h = handlerInternalError(err)
			return
		}
		rd := bytes.NewReader([]byte(out))
		h = handlerReader("pug "+filename, rd)
	case strings.HasSuffix(filename, ".redirect"):
		url, err := ioutil.ReadFile(filename)
		if err != nil {
			h = handlerInternalError(err)
		}
		h = handlerRedirect(string(url))
	default:
		h = handlerLiteralFile(filename)
	}
}

// ServeHTTP handles requests. It first authenticates using Digest Access
// Authentication if necessary. Literal matches to the path are served
// first, followed by files matching an implicit extension, and finally
// a directory index if applicable.
func (s *server) ServeHTTP(ctx *fasthttp.RequestCtx) {
	if s.tls.port != "" {
		ctx.Response.Header.Add("Strict-Transport-Security", "max-age=63072000")
	}
	if s.checkTLSRedirect(ctx, requiredAll) {
		return
	}

	pathStr := string(ctx.Path())
	if len(pathStr) > 1 {
		splits := strings.Split(pathStr, "/")
		if len(splits) > 1 {
			route := splits[1]
			_, isSecret := s.secret[route]
			if isSecret {
				if s.checkTLSRedirect(ctx, requiredSecrets) {
					return
				}
				ok := s.checkAuth(ctx, route)
				if !ok {
					s.sendChallenge(ctx, route)
					return
				}
			}
		}
	}

	if s.cache != nil {
		h, ok := s.cache.Get(pathStr)
		if ok {
			log.Printf("found in cache: %s", pathStr)
			h.(fasthttp.RequestHandler)(ctx)
			return
		}
	}

	path := fp.Join(s.path, pathStr)

	// follow symbolic links
	link, err := os.Readlink(path)
	if err == nil {
		path = link
	}

	// serve literal files
	fi, err := os.Stat(path)
	if err == nil && !fi.IsDir() {
		h := handlerLiteralFile(path)
		if s.cache != nil {
			s.cache.Set(pathStr, h, cache.DefaultExpiration)
		}
		h(ctx)
		return
	}

	files, err := ioutil.ReadDir(fp.Dir(path))
	if err != nil {
		h := handlerNotFound()
		if s.cache != nil {
			s.cache.Set(pathStr, h, cache.DefaultExpiration)
		}
		h(ctx)
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
		s.serveFilteredFile(ctx, filename)
		return
	}

	fi, err = os.Stat(path)
	if err != nil {
		h := handlerNotFound()
		if s.cache != nil {
			s.cache.Set(pathStr, h, cache.DefaultExpiration)
		}
		h(ctx)
		return
	}

	// directory requested, force trailing "/"
	if !strings.HasSuffix(pathStr, "/") {
		h := fasthttp.RequestHandler(func(ctx *fasthttp.RequestCtx) {
			ctx.Redirect(pathStr+"/", fasthttp.StatusMovedPermanently)
			log.Printf(logf, ctx.Method(), pathStr, fasthttp.StatusMovedPermanently, "")
		})
		if s.cache != nil {
			s.cache.Set(pathStr, h, cache.DefaultExpiration)
		}
		h(ctx)
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
		s.serveFilteredFile(ctx, filename)
		return
	}

	h := handlerNotFound()
	if s.cache != nil {
		s.cache.Set(pathStr, h, cache.DefaultExpiration)
	}
	h(ctx)
}

func (s *server) checkTLSRedirect(ctx *fasthttp.RequestCtx, cond int) bool {
	if s.tls.required != cond || ctx.IsTLS() {
		return false
	}
	ctx.Redirect(fmt.Sprintf("https://%s%s", s.host, ctx.Path()), fasthttp.StatusSeeOther)
	return true
}
