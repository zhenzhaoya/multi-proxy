package config

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/zhenzhaoya/multiproxy/utils"
)

var logger = log.New(os.Stderr, "multiproxy:", log.Llongfile|log.LstdFlags)

type ProxyEx struct {
	All   []string
	Http  []string
	Https []string
}
type DomainSub struct {
	Url        string // 遇到时进行cookie，useragent，ip等缓存。同时清除cookie，修改useragent、ip
	Domain     string
	Cookie     string
	CookiePath string
	Proxy      bool
}
type DomainEx struct {
	Allow    []*DomainSub
	NotAllow []string
}
type LogEx struct {
	Url       bool
	Body      bool
	Header    bool
	HeaderKey []string
	Allow     []string
	NotAllow  []string
}

type Config struct {
	Addr      string
	Proxy     *ProxyEx
	Domain    *DomainEx
	UserAgent []string
	Log       *LogEx
	Port      string
}

func (self *Config) GetProxy(proto string) string {
	proxy := self.Proxy
	l := 0
	if proxy.All != nil {
		l += len(proxy.All)
	}
	// if proto=="https" && proxy.Https!=nil{
	// 	l += len(proxy.Https)
	// }
	if l == 1 {
		return proxy.All[0]
	} else if l > 1 {
		return proxy.All[utils.GetRandNum(0, l)]
	}
	return ""
}

func (self *Config) GetUserAgent() string {
	if self.UserAgent != nil {
		l := len(self.UserAgent)
		if l == 1 {
			return self.UserAgent[0]
		} else if l > 1 {
			return self.UserAgent[utils.GetRandNum(0, l)]
		}
	}
	return ""
}

// func GetRandNum(min int, max int) int {
// 	if max <= min {
// 		return min
// 	}
// 	rand.Seed(time.Now().UnixNano())
// 	var i int = rand.Intn(max-min) + min
// 	return i
// }
// func Atoi(s string, d int) int {
// 	i, err := strconv.Atoi(s)
// 	if err == nil {
// 		return i
// 	}
// 	return d
// }
func Json2Config(b []byte) (*Config, error) {
	c := &Config{}
	err := json.Unmarshal(b, &c)
	i := strings.LastIndex(c.Addr, ":")
	if c.Port == "" && i >= 0 {
		c.Port = c.Addr[i:]
	}
	return c, err
}
func NewConfig(configPath string) *Config {
	c := &Config{}
	dat, err := ioutil.ReadFile(configPath)
	if err == nil {
		c, err = Json2Config(dat)
		if err != nil {
			logger.Println("error: ", err)
		}
	}
	if err != nil {
		c.Addr = ":8080"
		c.Port = "8080"
	}
	return c
}
