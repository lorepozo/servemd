# servemd

__`servemd`__ is a minimal server which supports markdown, authentication
for secured paths, and (optionally) TLS. Files are served in accordance with
their MIME type, allowing for native viewing (e.g. PDFs or videos on
mobile). The example directory shows typical usage (viewable live
[here](http://docs.lucasem.com:8000)), which could look as follows:

```
.
├── docs
│   ├── secret
│   │   └── index.md
│   ├── index.md
│   ├── page.html
│   ├── paper.pdf
│   └── video.mp4
├── md.tpl
└── settings.yaml
```

This would serve paths `/`, `/paper`, `/paper.pdf`, `/page`, `/video`, etc.
The path `/secret` (and any requests therein), if secured according to the
settings file (see below), will require password authentication to view.

## Installation

```
go get github.com/lucasem/servemd
```

## Usage

To run the server, simply run:
```sh
servemd settings.yaml
```

The settings.yaml file specifies the location of the serving directory and
the markdown template, as well as the port and any secured root paths. If
you want to use HTTPS/TLS, you can also specify the certificate and matching
private key.
```yaml
dir: path/to/docs
port: 80                       # optional, defaults to 80
host: localhost                # optional, defaults to kernel-reported hostname
template: path/to/md.tpl
secrets:                       # optional
  my_dir: my_password
  other_dir: other_password
tls:                           # optional
  required: secrets            # more optional, 'all' or 'secrets' (or '')
  port: 443                    # more optional, defaults to '443'
  cert: cert.pem
  privkey: privkey.pem
```

The template file uses the format described in
[text/template](http://golang.org/pkg/text/template) with `{{ .Content }}`
substituted by the HTML from converted markdown.

When specifying TLS, two servers (one HTTP and one HTTPS) will be spawned if
and only if `tls.required` is _not_ set to `all`.

__`servemd`__ first authenticates using HTTP Digest Access Authentication
([RFC 2617](https://tools.ietf.org/html/rfc2617)) if necessary. Literal
matches to the path are served first, followed by files matching an
implicit extension, and finally a directory index if applicable.

Markdown is parsed using
[blackfriday](https://github.com/russross/blackfriday)'s `MarkdownCommon`
implementation, which features common extensions including fenced code
blocks and strikethroughs. Syntax highlighting can be done easily with
[Prism](http://prismjs.com) in the markdown template.

