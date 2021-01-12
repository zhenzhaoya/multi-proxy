package multiproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/elazarl/goproxy"
	"github.com/zhenzhaoya/multiproxy/config"
)

type H map[string]string
type CookieCache struct {
	Proxy  string
	Cookie []string
}

type UserCache struct {
	Cookie    []string
	UserAgent string
	Proxy     string
	Sid       string
	Count     int
}

type ProxyEx struct {
	userCache     map[string][]*UserCache //[domain][]{Cookie,UserAgent,IP}
	config        *config.Config
	useProxy      bool
	collectCookie bool

	BeforeRequest func(http.ResponseWriter, *http.Request) bool
	AfterResponse func(*http.Response, *http.Request)
}

func json2userCache(b []byte) (map[string][]*UserCache, error) {
	c := make(map[string][]*UserCache)
	err := json.Unmarshal(b, &c)
	return c, err
}

var logger = log.New(os.Stderr, "multi-proxy:", log.Llongfile|log.LstdFlags)

func GetAPP() *ProxyEx {
	app := &ProxyEx{userCache: make(map[string][]*UserCache), collectCookie: true}
	return app
}

// func (self *ProxyEx) HandleConnect(req string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
// 	logger.Println(req)
// 	c := &goproxy.ConnectAction{Action: goproxy.ConnectHijack,
// 		Hijack: func(r *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
// 	defer func() {
// 		if e := recover(); e != nil {
// 			ctx.Logf("error connecting to remote: %v", e)
// 			client.Write([]byte("HTTP/1.1 500 Cannot reach destination\r\n\r\n"))
// 		}
// 		client.Close()
// 	}()
// 	logger.Println(r.RequestURI)
// 	clientBuf := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))

// 	remote, _ := net.Dial("tcp", r.URL.Host)
// 	client.Write([]byte("HTTP/1.1 200 Ok\r\n\r\n"))
// 	remoteBuf := bufio.NewReadWriter(bufio.NewReader(remote), bufio.NewWriter(remote))
// 	for {
// 		requ, err := http.ReadRequest(clientBuf.Reader)
// 		if err == nil {
// 			resp, err := http.ReadResponse(remoteBuf.Reader, requ)
// 			if err == nil {
// 				buf, _ := getBufferFromResp(resp)
// 				logger.Println(string(buf))
// 			} else {
// 				logger.Println(err)
// 			}
// 		} else {
// 			logger.Println(err)
// 		}
// 	}
// 		},
// 		TLSConfig: func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {

// 			return nil, nil
// 		}}
// 	return c, req
// }

func (self *ProxyEx) Start(config *config.Config) {
	self.config = config

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		self.localHandler(w, req)
	})

	// proxy.OnRequest().HandleConnect(self)
	proxy.OnRequest().DoFunc(
		func(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			if self.beforeRequest(r) { // API
				return r, nil
			}

			cache := self.setCookie(r)
			self.setUserAgent(r, cache)

			var tr *http.Transport = nil
			var res *http.Response = nil
			var err error = nil
			p := self.getProxy(r, cache)
			if p != "" {
				proxyUrl, _ := url.Parse("http://" + p)
				tr = &http.Transport{
					Proxy:              http.ProxyURL(proxyUrl),
					TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
					DisableCompression: true,
				}
				ctx.UserData = p
				res, err = tr.RoundTrip(r)
			} else {
				res, err = http.DefaultTransport.RoundTrip(r)
			}
			if err != nil {
				res.StatusCode = http.StatusServiceUnavailable
			}
			return r, res
		})

	proxy.OnResponse().DoFunc(func(res *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		r := ctx.Req
		p := ""
		if ctx.UserData != nil {
			p = ctx.UserData.(string)
		}
		self.afterResponse(res, r, p) // API
		cookies := self.cacheCookie(res, r, p)
		if cookies != nil {
			clearCookie(res, cookies)
			res.Header.Set("Content-type", "application/json")
			setResponseBodyWithStr(res, GetResponse(200, "success"))
		} else {

			copyHeader(res.Header, res.Header)
			setResponseBodyWithReader(res, res.Body)
		}
		return res

	})
	log.Fatal(http.ListenAndServe(config.Addr, proxy))
}

func genCertificate() (cert tls.Certificate, err error) {
	rawCert, rawKey, err := generateKeyPair()
	if err != nil {
		return
	}
	return tls.X509KeyPair(rawCert, rawKey)
}

func generateKeyPair() (rawCert, rawKey []byte, err error) {
	// Create private key and self-signed certificate
	// Adapted from https://golang.org/src/crypto/tls/generate_cert.go

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return
	}
	validFor := time.Hour * 24 * 365 * 10 // ten years
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Zarten"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return
	}

	rawCert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	rawKey = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return
}
