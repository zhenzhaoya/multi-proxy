package multiproxy

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/zhenzhaoya/goproxy"
)

type Cache struct {
	m sync.Map
}

type EventHandler struct {
	ProxySelf *ProxyEx
}

func (c *Cache) Set(host string, cert *tls.Certificate) {
	c.m.Store(host, cert)
}
func (c *Cache) Get(host string) *tls.Certificate {
	v, ok := c.m.Load(host)
	if !ok {
		return nil
	}

	return v.(*tls.Certificate)
}

func (e *EventHandler) NonproxyHandler(w http.ResponseWriter, req *http.Request) {
	self := e.ProxySelf
	self.localHandler(w, req)
}

func (e *EventHandler) Connect(ctx *goproxy.Context, w http.ResponseWriter) {
	// 保存的数据可以在后面的回调方法中获取
	ctx.Data["req_id"] = "uuid"

	// 禁止访问某个域名
	if strings.Contains(ctx.Req.URL.Host, "example.com") {
		w.WriteHeader(http.StatusForbidden)
		ctx.Abort()
		return
	}
}

func (e *EventHandler) Auth(ctx *goproxy.Context, rw http.ResponseWriter) {
	// 身份验证
}

func (e *EventHandler) BeforeRequest(ctx *goproxy.Context) {
	// self := e.ProxySelf
	// self.logRequest(ctx.Req)
	// 修改header
	// ctx.Req.Header.Add("X-Request-Id", ctx.Data["req_id"].(string))
	// // 设置X-Forwarded-For
	// if clientIP, _, err := net.SplitHostPort(ctx.Req.RemoteAddr); err == nil {
	// 	if prior, ok := ctx.Req.Header["X-Forwarded-For"]; ok {
	// 		clientIP = strings.Join(prior, ", ") + ", " + clientIP
	// 	}
	// 	ctx.Req.Header.Set("X-Forwarded-For", clientIP)
	// }
	// // 读取Body
	// body, err := ioutil.ReadAll(ctx.Req.Body)
	// if err != nil {
	// 	// 错误处理
	// 	return
	// }
	// // Request.Body只能读取一次, 读取后必须再放回去
	// // Response.Body同理
	// ctx.Req.Body = ioutil.NopCloser(bytes.NewReader(body))

}

func (e *EventHandler) BeforeResponse(ctx *goproxy.Context, resp *http.Response, err error) {
	if err != nil {
		return
	}
	self := e.ProxySelf
	r := ctx.Req
	p := ""
	if len(r.Header["self_data_p"]) > 0 {
		p = r.Header["self_data_p"][0]
		r.Header.Del("self_data_p")
	}
	self.afterResponse(resp, r, p) // API
	path, cookies := self.cacheCookie(resp, r, p)
	if self.collectCookie && cookies != nil {
		clearCookie(resp, cookies, path)
		resp.Header.Add("Content-type", "application/json")
		setResponseBodyWithStr(resp, GetResponse(200, "success"))
	}
	// 修改response
}

// 设置上级代理
func (e *EventHandler) ParentProxy(req *http.Request) (*url.URL, error) {
	self := e.ProxySelf
	cache := self.setCookie(req)
	self.setUserAgent(req, cache)
	p := self.getProxy(req, cache)

	self.logRequest(req)

	if p != "" {
		req.Header.Add("self_data_p", p)
		return &url.URL{Scheme: req.URL.Scheme, Host: p}, nil
	}
	return nil, nil
}

func (e *EventHandler) Finish(ctx *goproxy.Context) {
	// log.Printf("请求结束 URL:%s\n", ctx.Req.URL)
}

// 记录错误日志
func (e *EventHandler) ErrorLog(ctx *goproxy.Context, err error, tag string) {
	if strings.HasPrefix(tag, "HTTPS解密") {
		return
	}
	log.Println(tag, err)
}
