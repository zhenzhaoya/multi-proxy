package multiproxy

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/zhenzhaoya/goproxy"
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
	server        *http.Server

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

func (self *ProxyEx) Start(config *config.Config) {
	self.config = config

	proxy := goproxy.New(goproxy.WithDelegate(&EventHandler{ProxySelf: self}), goproxy.WithDecryptHTTPS(&Cache{}))
	server := &http.Server{
		Addr:         config.Addr,
		Handler:      proxy,
		ReadTimeout:  1 * time.Minute,
		WriteTimeout: 1 * time.Minute,
	}
	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}
