package main

import (
	"github.com/elazarl/goproxy"
	"github.com/pangolinfq/golibfq/http2socks"
	"net"
	"net/http"
)

type goproxyHTTP2SocksConverter struct {
	converter http2socks.Converter
}

func (c *goproxyHTTP2SocksConverter) goproxyHTTP2Socks(r *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	resp, err := c.converter.HTTP(r)
	if err != nil {
		goproxy.NewResponse(r, goproxy.ContentTypeText, http.StatusBadGateway, "Failed to forward to SOCKS proxy")
	}
	return r, resp
}

func (c *goproxyHTTP2SocksConverter) goproxyHTTPS2Socks(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
	r := ctx.Req
	resp, socksConn := c.converter.HTTPSConnect(r)
	if resp.StatusCode != 200 {
		return goproxy.RejectConnect, host
	}
	return &goproxy.ConnectAction{Action: goproxy.ConnectHijack, Hijack: func(r *http.Request, client net.Conn, ctx *goproxy.ProxyCtx) {
		c.converter.HTTPS(client, socksConn)
	}}, host
}
