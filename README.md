# servemd

__`servemd`__ is an minimalist HTTP server which supports markdown, pug
(formerly jade), authentication for secured paths, caching, and TLS. Files
are served in accordance with their MIME type, allowing for native viewing
(e.g.  PDFs or videos on mobile). The example directory shows typical usage
(viewable live [here](https://docs.lucasem.com:8000)), which could look as
follows:

```sh
.
├── secret         #(you can require auth for this dir)
│   └── index.md   # /secret
├── index.md       # / or /index
├── page.html      # /page.html or /page
├── paper.pdf      # /paper.pdf or /paper
└── video.mp4      # /video.mp4 or /video
```

## Installation

```
go get github.com/lucasem/servemd
```

## Usage

To run the server, simply run:
```sh
servemd settings.yaml
```

The settings.yaml file specifies all configuration information for the
server. The only required field is `dir`, the path to serve.
```yaml
dir: path/to/docs              # required
port: 8080                     # optional, defaults to 80
host: localhost                # optional, defaults to kernel-reported hostname
log: server.log                # optional, log file; defaults to stderr
template: path/to/md.tpl       # optional, but you should set it
ttl: 240                       # optional, defaults to 0 (in minutes)
secrets:                       # optional
  my_dir: my_password
  other_dir: other_password
tls:                           # optional
  cert: fullchain.pem          # TLS required
  privkey: privkey.pem         # TLS required
  only: false                  # optional, defaults to false
  required: secrets            # optional, 'all', 'secrets', or 'none' (default)
  port: 8443                   # optional, defaults to 443
```

### Markdown and Pug(/Jade)
Markdown is parsed using
[blackfriday](https://github.com/russross/blackfriday)'s `MarkdownCommon`
implementation, which features common extensions including fenced code
blocks and strikethroughs. Syntax highlighting can be done easily with
[Prism](http://prismjs.com) in the markdown template.

The template file uses the format described in
[text/template](http://golang.org/pkg/text/template) with `{{ .Content }}`
substituted by the HTML from rendered markdown. See the
[example template](./example/md.tpl).

Pug files are automatically rendered before a request is served.

### Caching
Caching is enabled by setting `ttl` to a non-zero value (in minutes). If ttl
is negative, the cache will never expire any cached response. The cache can
be forced to flushed by sending SIGUSR1 to the __`servemd`__ process:
```sh
$ servemd settings.yaml &
$ PID=$!
$ kill -USR1 $PID  # clear the cache
```

Caching is particularly useful when serving markdown and pug files, because
these files will never have to be re-rendered (dramatically reducing
response time) until they expire.

### Secrets and Authentication
__`servemd`__ authenticates using HTTP Digest Access Authentication ([RFC
2617](https://tools.ietf.org/html/rfc2617)). The username isn't affirmed,
only the password needs to match.

### TLS
The configuration __`servemd`__ uses for TLS yields an **A+** on SSL Labs!
When specifying TLS, two servers (one HTTP and one HTTPS) will be spawned
unless `tls.only` is set to `true`.

The `required` option, when set to `all`, will redirect all HTTP traffic to
use HTTPS. When set to `secrets`, this is only done for traffic that hits a
secret path (if at least this isn't set, then your secrets may not be very
secret because it's very easy to read HTTP traffic over wifi).
