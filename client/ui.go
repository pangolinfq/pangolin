package main

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"

	"github.com/getlantern/i18n"
	"github.com/skratchdot/open-golang/open"
)

var (
	templateFuncMap = template.FuncMap{
		"i18n": i18n.T,
	}
)

const (
	settingsTemplate = `
<!DOCTYPE html>
<html>
<head>
<title>{{ i18n "UI_TITLE" }}</title>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<script type="text/javascript" src="/static/js/jquery-1.11.3.min.js"></script>
</head>
<body>
<p>
<h1>{{ .Version }}</h1>
</p>

<p>
<img src="/static/icons/128.ico" alt="Pangolin"></img>
</p>

<div id="alert">
</div>

<h2>{{ i18n "UI_ADDR" }}</h2>
<ul style="list-style: none;">
<li>{{ i18n "UI_HTTPADDR" }}: {{ .HTTPProxyAddr }} </li>
<li>{{ i18n "UI_SOCKSADDR" }}: {{ .SocksProxyAddr }} </li>	
</ul>

<h2>{{ i18n "UI_SETTINGS" }}</h2>
<ul style="list-style: none;">
<li><label><input type="checkbox" id="tunnelingAll" {{ if .TunnelingAll }} checked {{ end }}> {{ i18n "UI_PROXY_ALL" }} </label></li>
<li><label><input type="checkbox" id="openSettingsPage" {{ if .OpenSettingsPage }} checked {{ end }}> {{ i18n "UI_SETTINGS_PAGE" }}</label></li>
<li><label><input type="checkbox" id="openLandingPage" {{ if .OpenLandingPage }} checked {{ end }}> {{ i18n "UI_LANDING_PAGE" }}: <a href={{ .LandingPage }} target="_blank">{{ .LandingPage }}</a></label></li>
</ul>

<script>
$(document).ready(function(e) {
	if( /firefox/.test(navigator.userAgent.toLowerCase()) ) {
		$("#alert").append("<h3><strong>{{ i18n "UI_FIREFOXHELP" }}</strong></h3>")
	}
}); 
  	
  	$("input:checkbox").change(function() { 
    	var isChecked = $(this).is(":checked") ? 1:0; 
        $.ajax({
        	url: '/settings',
            type: 'POST',
            data: { id:$(this).attr("id"), state:isChecked }
        });        
    });        
</script>

</body>
</html>
	`
)

type pangolinUI struct {
	mux         *http.ServeMux
	root        string
	settingsUrl string
	client      *pangolinClient
}

func startUI(c *pangolinClient, l net.Listener) *pangolinUI {
	ui := &pangolinUI{
		root:        fmt.Sprintf("http://%s", l.Addr().String()),
		settingsUrl: fmt.Sprintf("http://%s/settings", l.Addr().String()),
		mux:         http.NewServeMux(),
		client:      c,
	}
	ui.mux.Handle("/settings", http.HandlerFunc(ui.settings))
	ui.mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(c.fs)))
	go func() {
		server := &http.Server{
			Handler: ui.mux,
		}
		err := server.Serve(l)
		if err != nil {
			log.Fatalf("FATAL: UI stopped")
		}
		ui.client.exit(err)
	}()
	return ui
}

func (u *pangolinUI) handle(path string, handler http.Handler) string {
	u.mux.Handle(path, handler)
	return u.root + path
}

func (u *pangolinUI) show() {
	open.Start(u.settingsUrl)
}

func (u *pangolinUI) open(url string) {
	open.Start(url)
}

func (u *pangolinUI) settings(w http.ResponseWriter, req *http.Request) {
	if req.Method == "GET" {
		u.settingsGET(w, req)
	} else if req.Method == "POST" {
		u.settingsPOST(w, req)
	} else {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

type pangolinSettings struct {
	Version          string
	HTTPProxyAddr    string
	SocksProxyAddr   string
	LandingPage      string
	TunnelingAll     bool
	OpenSettingsPage bool
	OpenLandingPage  bool
}

func (u *pangolinUI) settingsGET(w http.ResponseWriter, req *http.Request) {
	t, err := template.New("settings").Funcs(templateFuncMap).Parse(settingsTemplate)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	settings := &pangolinSettings{
		Version:          u.client.version(),
		HTTPProxyAddr:    u.client.httpListener.Addr().String(),
		SocksProxyAddr:   u.client.socksListener.Addr().String(),
		LandingPage:      u.client.options.landingPage,
		TunnelingAll:     u.client.socksHandler.tunnelingAll,
		OpenSettingsPage: u.client.openSettingsPage(),
		OpenLandingPage:  u.client.openLandingPage(),
	}
	err = t.Execute(w, settings)
	if err != nil {
		log.Printf("template execute error: %s", err)
	}
}

func (u *pangolinUI) settingsPOST(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
	id := req.FormValue("id")
	state := req.FormValue("state")
	switch id {
	case "tunnelingAll":
		if state == "1" {
			u.client.tunnelingAllOn()
		} else {
			u.client.tunnelingAllOff()
		}
	case "openSettingsPage":
		if state == "1" {
			u.client.openSettingsPageOn()
		} else {
			u.client.openSettingsPageOff()
		}
	case "openLandingPage":
		if state == "1" {
			u.client.openLandingPageOn()
		} else {
			u.client.openLandingPageOff()
		}
	default:
		http.Error(w, "Unexpected settings option", http.StatusBadRequest)
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}
