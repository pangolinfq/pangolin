package main

import (
	"github.com/elazarl/goproxy"
	"github.com/pangolinfq/golibfq/http2socks"
	"net"
	"net/http"
)

type goproxyHttp2SocksConverter struct {
	converter http2socks.Http2SocksConverter
}

func (c *goproxyHttp2SocksConverter) goproxyHttp2Socks(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	resp, err := c.converter.Http(r)
	if err != nil {
		goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusBadGateway, "Failed to forward to SOCKS proxy")
	}
	return r, resp
}

func (c *goproxyHttp2SocksConverter) goproxyHttps2Socks(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	r := ctx.Req
	resp, socksConn := c.converter.HttpsConnect(r)
	if resp.StatusCode != 200 {
		return goproxy.RejectConnect, host
	}
	return &goproxy.ConnectAction{Action: goproxy.ConnectHijack, Hijack: func(r *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
		c.converter.Https(client, socksConn)
	}}, host
}
