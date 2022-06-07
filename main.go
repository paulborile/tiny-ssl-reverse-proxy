package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/sensiblecodeio/tiny-ssl-reverse-proxy/proxyprotocol"
)

// Version number
const Version = "0.21.0"

var message = `<!DOCTYPE html><html>
<head>
<title>
Backend Unavailable
</title>
<style>
body {
	font-family: fantasy;
	text-align: center;
	padding-top: 20%;
	background-color: #f1f6f8;
}
</style>
</head>
<body>
<h1>503 Backend Unavailable</h1>
<p>Sorry, we&lsquo;re having a brief problem. You can retry.</p>
<p>If the problem persists, please get in touch.</p>
</body>
</html>`

type ConnectionErrorHandler struct{ http.RoundTripper }

func (c *ConnectionErrorHandler) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.RoundTripper.RoundTrip(req)
	if err != nil {
		log.Printf("Error: backend request failed for %v: %v",
			req.RemoteAddr, err)
	}
	if _, ok := err.(*net.OpError); ok {
		r := &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       ioutil.NopCloser(bytes.NewBufferString(message)),
		}
		return r, nil
	}
	return resp, err
}

func main() {
	var (
		listen, cert, key, where           string
		useTLS, useLogging, behindTCPProxy bool
		flushInterval                      time.Duration
	)
	flag.StringVar(&listen, "listen", "localhost:443", "Bind address to listen on")
	flag.StringVar(&key, "key", "/etc/ssl/private/key.pem", "Path to PEM key")
	flag.StringVar(&cert, "cert", "/etc/ssl/private/cert.pem", "Path to PEM certificate")
	flag.StringVar(&where, "where", "https://www.imageengine.io/", "Place to forward connections to")
	flag.BoolVar(&useTLS, "tls", true, "accept HTTPS connections")
	flag.BoolVar(&useLogging, "logging", true, "log requests")
	flag.BoolVar(&behindTCPProxy, "behind-tcp-proxy", false, "running behind TCP proxy (such as ELB or HAProxy)")
	flag.DurationVar(&flushInterval, "flush-interval", 0, "minimum duration between flushes to the client (default: off)")
	oldUsage := flag.Usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "\n%v version %v\n\n", os.Args[0], Version)
		oldUsage()
	}
	flag.Parse()

	url, err := url.Parse(where)
	if err != nil {
		log.Fatalln("Fatal parsing -where:", err)
	}

	httpProxy := httputil.NewSingleHostReverseProxy(url)
	httpProxy.Transport = &ConnectionErrorHandler{http.DefaultTransport}
	httpProxy.FlushInterval = flushInterval
	httpProxy.ModifyResponse = rewriteBody

	var handler http.Handler

	handler = httpProxy

	originalHandler := handler
	handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/_version" {
			w.Header().Add("X-Tiny-SSL-Version", Version)
		}
		// r.Header.Set("X-Forwarded-Proto", "https")
		// fmt.Printf("Host header set : %s\n", r.Host)
		// reset the where param if we find a url= in request

		siteToProxy, ok := r.URL.Query()["_url"]

		if ok && len(siteToProxy[0]) > 0 {
			site := siteToProxy[0]
			url, err = url.Parse(site)
			r.URL.Query().Del("_url")
			if err == nil {
				// add HOST header
				r.Host = url.Host
				log.Printf("New Site to proxy to = %s\n", site)
				originalHandler := httputil.NewSingleHostReverseProxy(url)
				originalHandler.Transport = &ConnectionErrorHandler{http.DefaultTransport}
				originalHandler.FlushInterval = flushInterval
				originalHandler.ServeHTTP(w, r)
			}
		} else {
			// add current redirect site (last url=) header
			r.Host = url.Host
			originalHandler.ServeHTTP(w, r)
		}

		// set some response headers

	})

	if useLogging {
		handler = &LoggingMiddleware{handler}
	}

	server := &http.Server{Addr: listen, Handler: handler}

	switch {
	case useTLS && behindTCPProxy:
		err = proxyprotocol.BehindTCPProxyListenAndServeTLS(server, cert, key)
	case behindTCPProxy:
		err = proxyprotocol.BehindTCPProxyListenAndServe(server)
	case useTLS:
		err = server.ListenAndServeTLS(cert, key)
	default:
		err = server.ListenAndServe()
	}

	log.Fatalln(err)
}

func rewriteBody(resp *http.Response) (err error) {
	b, err := ioutil.ReadAll(resp.Body) //Read html
	fmt.Printf("%s\n", b)
	if err != nil {
		return err
	}
	err = resp.Body.Close()
	if err != nil {
		return err
	}
	b = bytes.Replace(b, []byte("background"), []byte("Background"), -1) // replace html
	body := ioutil.NopCloser(bytes.NewReader(b))
	resp.Body = body
	resp.ContentLength = int64(len(b))
	resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
	resp.Header.Add("Content-Security-Policy",
		"default-src * 'unsafe-inline' 'unsafe-eval'; img-src * data:; script-src * ; script-src-elem * 'unsafe-inline' ; font-src * data:")
	resp.Header.Add("Access-Control-Allow-Origin", "*")

	return nil
}
