package utils

import (
	"net/http"
	"time"

	"hubproxy/config"
)

var (
	globalHTTPClient *http.Client
	searchHTTPClient *http.Client
)

// InitHTTPClients 初始化HTTP客户端
func InitHTTPClients() {
	cfg := config.GetConfig()

	globalPolicy := newEgressPolicy(cfg, 30*time.Second)
	searchPolicy := newEgressPolicy(cfg, 5*time.Second)

	globalHTTPClient = &http.Client{
		Transport: &guardedTransport{policy: globalPolicy, next: &http.Transport{
			DialContext:           globalPolicy.dialContext,
			MaxIdleConns:          1000,
			MaxIdleConnsPerHost:   1000,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			ResponseHeaderTimeout: 300 * time.Second,
		}},
	}

	searchHTTPClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &guardedTransport{policy: searchPolicy, next: &http.Transport{
			DialContext:         searchPolicy.dialContext,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 5 * time.Second,
			DisableCompression:  false,
		}},
	}
}

// GetGlobalHTTPClient 获取全局HTTP客户端
func GetGlobalHTTPClient() *http.Client {
	return globalHTTPClient
}

// GetSearchHTTPClient 获取搜索HTTP客户端
func GetSearchHTTPClient() *http.Client {
	return searchHTTPClient
}
