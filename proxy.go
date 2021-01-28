package multiproxy

import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	"github.com/zhenzhaoya/multiproxy/config"
	"github.com/zhenzhaoya/multiproxy/utils"
)

func getCookie(c string, r *http.Request) string {
	vv := r.Header["Cookie"]
	if vv != nil {
		for _, v := range vv {
			if strings.HasPrefix(v, c) {
				return v
			}
		}
	}
	return ""
}

func getAbsoluteUrl(req *http.Request) string {
	if strings.HasPrefix(req.RequestURI, "/") {
		return req.URL.Scheme + "://" + req.Host + req.RequestURI
	}
	return req.RequestURI
}

func (self *ProxyEx) getDomainSub(value string) *config.DomainSub {
	domain := self.config.Domain
	if domain == nil || domain.Allow == nil {
		return nil
	}
	arr := domain.Allow
	for k := range arr {
		if strings.Contains(value, arr[k].Domain) {
			return arr[k]
		}
	}
	return nil
}

func (self *ProxyEx) setUserAgent(r *http.Request, cache *UserCache) {
	config := self.config
	if config.UserAgent == nil || len(config.UserAgent) == 0 {
		return
	}

	if cache != nil && cache.UserAgent != "" {
		r.Header["User-Agent"] = []string{cache.UserAgent}
	} else {
		r.Header["User-Agent"] = []string{config.UserAgent[utils.GetRandNum(0, len(config.UserAgent))]}
	}
}

func (self *ProxyEx) getProxy(r *http.Request, cache *UserCache) string {
	config := self.config
	if !self.useProxy || config.Proxy == nil {
		return ""
	}

	domain := self.getDomainSub(r.Host)
	p := ""
	if domain != nil && domain.Proxy {
		if cache != nil {
			return cache.Proxy
		}

		if config.Proxy.All != nil && len(config.Proxy.All) > 0 {
			p = config.Proxy.All[utils.GetRandNum(0, len(config.Proxy.All))]
		}
	}
	return p
}

func (self *ProxyEx) setCookie(r *http.Request) *UserCache {
	if self.collectCookie {
		return nil // when collecting, do not modify
	}
	domain := self.getDomainSub(r.Host)
	if domain != nil && domain.Cookie != "" {
		var caches []*UserCache = self.userCache[r.Host]
		if caches != nil && len(caches) > 0 {
			v := caches[utils.GetRandNum(0, len(caches))]
			r.Header["Cookie"] = v.Cookie
			return v
		}
	}
	return nil
}

func (self *ProxyEx) cacheCookie(resp *http.Response, r *http.Request, p string) (string, []string) {
	domain := self.getDomainSub(r.Host)
	if domain != nil && domain.Cookie != "" {
		if domain.Url != "" && getAbsoluteUrl(r) != domain.Url {
			return "", nil
		}
		var caches []*UserCache = self.userCache[r.Host]
		if caches == nil {
			caches = make([]*UserCache, 0)
			self.userCache[r.Host] = caches
		}
		vv := resp.Cookies()
		kv := make(H)
		var cookie = []string{}
		sid := ""
		if vv != nil && len(vv) > 0 {
			for _, v := range vv {
				if v.Name == domain.Cookie {
					sid = v.Value
				}
				kv[v.Name] = "1"
				cookie = append(cookie, v.Name+"="+v.Value)
			}
		}
		if len(cookie) > 0 || getAbsoluteUrl(r) == domain.Url {
			cookies := r.Header["Cookie"]
			if cookies != nil && len(cookies) > 0 {
				for _, v := range cookies {
					k := strings.Split(v, "=")[0]
					if kv[k] != "" {
						continue
					}

					cookie = append(cookie, v)
					if sid == "" && strings.HasPrefix(v, domain.Cookie) {
						sid = strings.Split(v, "=")[1]
					}
				}
			}

			var cache *UserCache
			if !self.collectCookie {
				for i := range caches {
					if caches[i].Sid == sid {
						cache = caches[i]
						break
					}
				}
			}

			if cache == nil {
				if !self.collectCookie {
					logger.Println("warning: cache should not be empty.")
				}
				cache = &UserCache{}
				cache.UserAgent = r.Header["User-Agent"][0]
				cache.Proxy = p
				cache.Sid = sid
				cache.Cookie = cookie
				caches = append(caches, cache)
				self.userCache[r.Host] = caches
				return domain.CookiePath, cookie
			}
			cache.Cookie = cookie
		}
	}
	return "", nil
}

func clearCookie(w *http.Response, cookies []string, path string) {
	var value = ""
	for i := range cookies {
		cookie := http.Cookie{
			Name:  strings.Split(cookies[i], "=")[0],
			Value: "",
			Path:  path,
		}
		if value == "" {
			value = cookie.String() + "; Max-Age=-1"
		} else {
			value = value + "; " + cookie.String() + "; Max-Age=-1"
		}
	}
	if value == "" {
		w.Header.Del("Set-Cookie")
	} else {
		w.Header.Set("Set-Cookie", value)
	}
}

func (self *ProxyEx) logWriter(v ...interface{}) {
	if self.config.Log2File {
		logger.Println(v...)
	} else {
		log.Println(v...)
	}
}

func (self *ProxyEx) logRequest(req *http.Request) {
	config := self.config.Log
	if config.Allow != nil && len(config.Allow) > 0 {
		f := false
		for _, v := range config.Allow {
			if strings.Contains(req.Host, v) {
				f = true
				break
			}
		}
		if !f {
			return
		}
	}

	if config.Url {
		self.logWriter(req.Method, getAbsoluteUrl(req))
	}

	if config.Header {
		for k, vv := range req.Header {
			for _, v := range vv {
				self.logWriter(k, v)
			}
		}
	} else if config.HeaderKey != nil && len(config.HeaderKey) > 0 {
		for k, vv := range req.Header {
			if utils.ArrContains(config.HeaderKey, k) {
				for _, v := range vv {
					self.logWriter(k, v)
				}
			}
		}
	}

	if config.Body && req.Body != nil {
		b, err := ioutil.ReadAll(req.Body)
		if err == nil {
			self.logWriter(string(b))
			req.Body = ioutil.NopCloser(bytes.NewBuffer(b))
		}
	}
}

func (self *ProxyEx) handleHttps(w http.ResponseWriter, r *http.Request) {
	// if self.beforeRequest(w, r) { // API
	// 	return
	// }

	// cache := self.setCookie(r)
	// self.setUserAgent(r, cache)

	// var destConn net.Conn = nil
	// var err error = nil
	// destConn, err = net.DialTimeout("tcp", r.Host, 60*time.Second)
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusServiceUnavailable)
	// 	return
	// }
	// w.WriteHeader(http.StatusOK)

	// hijacker, ok := w.(http.Hijacker)
	// if !ok {
	// 	http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
	// 	return
	// }

	// clientConn, _, err := hijacker.Hijack()
	// if err != nil {
	// 	http.Error(w, err.Error(), http.StatusServiceUnavailable)
	// }

	// go transfer(destConn, clientConn)
	// go transfer(clientConn, destConn)
}

func (self *ProxyEx) afterResponse(resp *http.Response, r *http.Request, p string) {
	if self.AfterResponse != nil {
		self.AfterResponse(resp, r)
	}
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()

	io.Copy(destination, source)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func setResponseBodyWithStr(res *http.Response, buf string) {
	res.Body = ioutil.NopCloser(bytes.NewReader([]byte(buf)))
}

func setResponseBodyWithReader(res *http.Response, body io.ReadCloser) error {
	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}
	res.Body = ioutil.NopCloser(bytes.NewReader(buf))
	return nil
}

func setResponseBody(res *http.Response, buf []byte) {
	res.Body = ioutil.NopCloser(bytes.NewReader(buf))
}

func getBufferFromResp(res *http.Response) ([]byte, error) {
	buf, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	res.Body = ioutil.NopCloser(bytes.NewReader(buf))

	return buf, nil
}
