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

type server struct {
	// Path is the absolute path to the directory being served.
	Path string

	// Port is the port on which the server is being hosted.
	Port string

	// Host is the hostname of the server.
	Host string

	// Secret maps secured routes to their corresponding passwords.
	Secret map[string]string

	// mdTemplate for HTML generated from Markdown
	mdTemplate *template.Template
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
	log.Fatal(http.ListenAndServe(":"+s.Port, s))
}

// ServeHTTP handles requests. It first authenticates using Digest Access
// Authentication if necessary. Literal matches to the path are served
// first, followed by files matching an implicit extension, and finally
// a directory index if applicable.
func (s *server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if len(req.URL.Path) > 1 {
		splits := strings.Split(req.URL.Path, "/")
		if len(splits) > 1 {
			route := splits[1]
			_, isSecret := s.Secret[route]
			if isSecret {
				ok := s.checkAuth(req, route)
				if !ok {
					s.sendChallenge(w, req, route)
					return
				}
			}
		}
	}

	path := fp.Join(s.Path, req.URL.Path)
	fi, err := os.Stat(path)
	if err == nil {
		if !fi.IsDir() {
			// literal file exists
			http.ServeFile(w, req, path)
			log.Printf(logf, req.Method, req.URL.Path, http.StatusOK, "serving "+path)
			return
		}
	}

	files, err := ioutil.ReadDir(fp.Dir(path))
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		log.Printf(logf, req.Method, req.URL.Path, http.StatusNotFound, "")
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
		mdfile := fp.Join(fp.Dir(path), filtered)
		if strings.HasSuffix(filtered, ".md") {
			md, err := ioutil.ReadFile(mdfile)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				log.Printf(logf, req.Method, req.URL.Path, http.StatusInternalServerError, err.Error())
				return
			}
			out := blackfriday.MarkdownCommon(md)
			content := &templateContent{string(out)}
			s.mdTemplate.Execute(w, content)
			log.Printf(logf, req.Method, req.URL.Path, http.StatusOK, "markdown "+mdfile)
		} else {
			http.ServeFile(w, req, mdfile)
			log.Printf(logf, req.Method, req.URL.Path, http.StatusOK, "serving "+path)
		}
		return
	}

	fi, err = os.Stat(path)
	if err != nil {
		http.Error(w, "Not found", http.StatusNotFound)
		log.Printf(logf, req.Method, req.URL.Path, http.StatusNotFound, "")
		return
	}

	// directory requested, force trailing "/"
	if !strings.HasSuffix(req.URL.Path, "/") {
		http.Redirect(w, req, req.URL.Path+"/", http.StatusMovedPermanently)
		log.Printf(logf, req.Method, req.URL.Path, http.StatusMovedPermanently, "")
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
		mdfile := fp.Join(path, filtered)
		if strings.HasSuffix(filtered, ".md") {
			md, err := ioutil.ReadFile(mdfile)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				log.Printf(logf, req.Method, req.URL.Path, http.StatusInternalServerError, err.Error())
				return
			}
			out := blackfriday.MarkdownCommon(md)
			content := &templateContent{string(out)}
			s.mdTemplate.Execute(w, content)
			log.Printf(logf, req.Method, req.URL.Path, http.StatusOK, "markdown "+mdfile)
		} else {
			http.ServeFile(w, req, mdfile)
			log.Printf(logf, req.Method, req.URL.Path, http.StatusOK, "serving "+path)
		}
		return
	}

	http.Error(w, "Not found", http.StatusNotFound)
	log.Printf(logf, req.Method, req.URL.Path, http.StatusNotFound, "")
}

// settings is unmarshalled from a yaml file according to this
// specification.
type settings struct {
	Dir      string
	Port     string
	Template string
	Log      string
	Secrets  map[string]string
}

// toServer creates a server from the settings struct. The server host is
// determined using the host name reported by the kernel.
func (st settings) toServer(logFile io.Writer) *server {
	s := new(server)
	s.Path = st.Dir
	s.Port = st.Port
	host, err := os.Hostname()
	if err != nil {
		s.Host = "localhost"
	} else {
		s.Host = host
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
	s.Secret = st.Secrets
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
