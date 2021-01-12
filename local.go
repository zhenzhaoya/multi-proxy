package multiproxy

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/zhenzhaoya/multiproxy/config"
)

type SetData struct {
	CollectCookie bool
	UseProxy      bool
}

func Json2SetData(b []byte) (*SetData, error) {
	c := &SetData{}
	err := json.Unmarshal(b, &c)
	return c, err
}

type ResponseData struct {
	Code    int
	Message string
	Data    interface{}
}

func (res *ResponseData) ToJson() string {
	v, err := json.Marshal(res)
	if err == nil {
		return string(v)
	} else {
		return fmt.Sprintf(`{"Code":1000,"Message":"%v"}`, err.Error())
	}
}
func (res *ResponseData) Response(code int, message string) string {
	res.Code = code
	res.Message = message
	return res.ToJson()
}
func (res *ResponseData) Error(err error) string {
	if err == nil {
		return res.Success(nil)
	}
	res.Code = 1000
	res.Message = fmt.Sprintf(`%s`, err)
	return res.ToJson()
}
func (res *ResponseData) Success(data interface{}) string {
	res.Code = 0
	res.Message = "success"
	res.Data = data
	return res.ToJson()
}
func GetSuccessResponse(data interface{}) string {
	res := ResponseData{}
	return res.Success(data)
}
func GetResponse(code int, message string) string {
	res := ResponseData{}
	return res.Response(code, message)
}
func GetErrorResponse(err error) string {
	res := ResponseData{}
	return res.Error(err)
}

func setContentType(w http.ResponseWriter, url string) {
	if strings.HasSuffix(url, ".css") {
		w.Header().Set("Content-type", "text/css")
	} else if strings.HasSuffix(url, ".js") {
		w.Header().Set("Content-type", "application/x-javascript")
	} else if strings.HasSuffix(url, ".htm") || strings.HasSuffix(url, ".html") {
		w.Header().Set("Content-type", "text/html")
	} else if strings.HasSuffix(url, ".json") {
		w.Header().Set("Content-type", "application/json")
	} else if strings.HasSuffix(url, ".wasm") {
		w.Header().Set("Content-type", "application/wasm")
	} else {
		w.Header().Set("Content-type", "text/plain")
	}
}
func (self *ProxyEx) localHandler(w http.ResponseWriter, r *http.Request) bool {
	f := false
	for k, vv := range r.Header {
		if k == "SetHTTPProxy" {
			if vv[0] == self.config.Addr {
				f = true
			}
		}
	}

	if !f {
		f = r.Host == "localhost"+self.config.Port
	}

	if f {
		self.execHandler(w, r)
	}

	return f
}

func (self *ProxyEx) execHandler(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if r.Method == "GET" {
		if path == "/config" {
			w.Header().Set("Content-type", "application/json")
			io.WriteString(w, GetSuccessResponse(self.config))
			return
		} else if path == "/set" {
			w.Header().Set("Content-type", "application/json")
			data := &SetData{self.collectCookie, self.useProxy}
			io.WriteString(w, GetSuccessResponse(data))
			return
		} else if path == "/cache" {
			w.Header().Set("Content-type", "application/json")
			io.WriteString(w, GetSuccessResponse(self.userCache))
			return
		} else if strings.HasPrefix(path, "/static") {
			var _indexHtml = ""
			f, err := os.Open(path[1:])
			if err == nil {
				b, err := ioutil.ReadAll(f)
				if err == nil {
					_indexHtml = string(b)
				}
			}
			if err != nil {
				w.Header().Set("Content-type", "text/plain")
				_indexHtml = fmt.Sprintf(`%s`, err)
			}
			setContentType(w, path)
			io.WriteString(w, _indexHtml)
			return
		}
	} else if r.Method == "POST" {
		w.Header().Set("Content-type", "application/json")
		s, err := ioutil.ReadAll(r.Body)
		if path == "/config" {
			// fmt.Println(string(s))
			var c *config.Config
			if err == nil {
				c, err = config.Json2Config(s)
				if err == nil {
					self.config = c
					io.WriteString(w, GetSuccessResponse(nil))
					return
				}
			}
			io.WriteString(w, GetErrorResponse(err))
			return
		} else if path == "/set" {
			var c *SetData
			if err == nil {
				c, err = Json2SetData(s)
				if err == nil {
					self.useProxy = c.UseProxy
					self.collectCookie = c.CollectCookie
					io.WriteString(w, GetSuccessResponse(nil))
					return
				}
			}
			io.WriteString(w, GetErrorResponse(err))
			return
		} else if path == "/cache" {
			c, err := json2userCache(s)
			if err == nil {
				self.userCache = c
				io.WriteString(w, GetSuccessResponse(nil))
			} else {
				io.WriteString(w, GetErrorResponse(err))
			}
			return
		}
	}
}

// type SetData struct {
// 	CollectCookie bool
// 	UseProxy      bool
// }

// func Json2SetData(b []byte) (*SetData, error) {
// 	c := &SetData{}
// 	err := json.Unmarshal(b, &c)
// 	return c, err
// }

// type ResponseData struct {
// 	Code    int
// 	Message string
// 	Data    interface{}
// }

// func (res *ResponseData) ToJson() string {
// 	v, err := json.Marshal(res)
// 	if err == nil {
// 		return string(v)
// 	} else {
// 		return fmt.Sprintf(`{"Code":1000,"Message":"%v"}`, err.Error())
// 	}
// }
// func (res *ResponseData) Response(code int, message string) string {
// 	res.Code = code
// 	res.Message = message
// 	return res.ToJson()
// }
// func (res *ResponseData) Error(err error) string {
// 	if err == nil {
// 		return res.Success(nil)
// 	}
// 	res.Code = 1000
// 	res.Message = fmt.Sprintf(`%s`, err)
// 	return res.ToJson()
// }
// func (res *ResponseData) Success(data interface{}) string {
// 	res.Code = 0
// 	res.Message = "success"
// 	res.Data = data
// 	return res.ToJson()
// }
// func GetSuccessResponse(data interface{}) string {
// 	res := ResponseData{}
// 	return res.Success(data)
// }
// func GetResponse(code int, message string) string {
// 	res := ResponseData{}
// 	return res.Response(code, message)
// }
// func GetErrorResponse(err error) string {
// 	res := ResponseData{}
// 	return res.Error(err)
// }

// func setContentType(w *http.Response, url string) {
// 	if strings.HasSuffix(url, ".css") {
// 		w.Header.Set("Content-type", "text/css")
// 	} else if strings.HasSuffix(url, ".js") {
// 		w.Header.Set("Content-type", "application/x-javascript")
// 	} else if strings.HasSuffix(url, ".htm") || strings.HasSuffix(url, ".html") {
// 		w.Header.Set("Content-type", "text/html")
// 	} else if strings.HasSuffix(url, ".json") {
// 		w.Header.Set("Content-type", "application/json")
// 	} else {
// 		w.Header.Set("Content-type", "text/plain")
// 	}
// }
// func (self *ProxyEx) localHandler(w *http.Response, r *http.Request) bool {
// 	f := false
// 	for k, vv := range r.Header {
// 		if k == "SetHTTPProxy" {
// 			if vv[0] == self.config.Addr {
// 				f = true
// 			}
// 		}
// 	}

// 	if !f {
// 		f = r.Host == "localhost"+self.config.Port
// 	}

// 	if f {
// 		self.execHandler(w, r)
// 	}

// 	return f
// }

// func (self *ProxyEx) execHandler(w *http.Response, r *http.Request) {
// 	path := r.URL.Path
// 	if r.Method == "GET" {
// 		if path == "/config" {
// 			w.Header.Set("Content-type", "application/json")
// 			setResponseBodyWithStr(w, GetSuccessResponse(self.config))
// 			return
// 		} else if path == "/set" {
// 			w.Header.Set("Content-type", "application/json")
// 			data := &SetData{self.collectCookie, self.useProxy}
// 			setResponseBodyWithStr(w, GetSuccessResponse(data))
// 			return
// 		} else if path == "/cache" {
// 			w.Header.Set("Content-type", "application/json")
// 			setResponseBodyWithStr(w, GetSuccessResponse(self.userCache))
// 			return
// 		} else if strings.HasPrefix(path, "/static") {
// 			var _indexHtml = ""
// 			f, err := os.Open(path[1:])
// 			if err == nil {
// 				b, err := ioutil.ReadAll(f)
// 				if err == nil {
// 					_indexHtml = string(b)
// 				}
// 			}
// 			if err != nil {
// 				w.Header.Set("Content-type", "text/plain")
// 				_indexHtml = fmt.Sprintf(`%s`, err)
// 			}
// 			setContentType(w, path)
// 			setResponseBodyWithStr(w, _indexHtml)
// 			return
// 		}
// 	} else if r.Method == "POST" {
// 		w.Header.Set("Content-type", "application/json")
// 		s, err := ioutil.ReadAll(r.Body)
// 		if path == "/config" {
// 			// fmt.Println(string(s))
// 			var c *config.Config
// 			if err == nil {
// 				c, err = config.Json2Config(s)
// 				if err == nil {
// 					self.config = c
// 					setResponseBodyWithStr(w, GetSuccessResponse(nil))
// 					return
// 				}
// 			}
// 			setResponseBodyWithStr(w, GetErrorResponse(err))
// 			return
// 		} else if path == "/set" {
// 			var c *SetData
// 			if err == nil {
// 				c, err = Json2SetData(s)
// 				if err == nil {
// 					self.useProxy = c.UseProxy
// 					self.collectCookie = c.CollectCookie
// 					setResponseBodyWithStr(w, GetSuccessResponse(nil))
// 					return
// 				}
// 			}
// 			setResponseBodyWithStr(w, GetErrorResponse(err))
// 			return
// 		} else if path == "/cache" {
// 			c, err := json2userCache(s)
// 			if err == nil {
// 				self.userCache = c
// 				setResponseBodyWithStr(w, GetSuccessResponse(nil))
// 			} else {
// 				setResponseBodyWithStr(w, GetErrorResponse(err))
// 			}
// 			return
// 		}
// 	}
// }
