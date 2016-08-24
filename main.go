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
	"io/ioutil"
	"log"
	"os"
	fp "path/filepath"

	"gopkg.in/yaml.v2"
)

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
