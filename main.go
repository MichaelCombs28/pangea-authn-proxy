package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	"github.com/pangeacyber/pangea-go/pangea-sdk/v3/pangea"
	"github.com/pangeacyber/pangea-go/pangea-sdk/v3/service/authn"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

const (
	defaultAuthRoute          = "/_internal/_auth/cnt6VjwxSXIpMCZUejQpJWUO29jeVBX"
	defaultAuthCookieName     = "pangeaProxyAuth"
	defaultStateCookieName    = "pangeaProxyState"
	defaultRedirectCookieName = "pangeaProxyRedirect"
)

var redirectContextKey *struct{} = new(struct{})

func main() {
	authnToken := getOrFail("PANGEA_AUTHN_TOKEN")
	pangeaDomain := getOrFail("PANGEA_DOMAIN")
	target := getOrFailURL("PROXY_TARGET")
	hostedPage := getOrFailURL("PANGEA_AUTHN_HOSTED_PAGE")
	host := getOrDefault("PROXY_HOST", "0.0.0.0")

	hostURL, err := url.Parse(host)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse host address")
	}

	secret := getOrFail("SECRET")

	authCookieName := getOrDefault("AUTH_COOKIE_NAME", defaultAuthCookieName)
	authRoute := getOrDefault("PROXY_AUTH_ROUTE", defaultAuthRoute)
	stateCookieName := getOrDefault("STATE_COOKIE_NAME", defaultStateCookieName)
	redirectCookieName := getOrDefault("REDIRECT_COOKIE_NAME", defaultRedirectCookieName)

	logLevel := getOrDefault("LOG_LEVEL", "info")
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to parse log level")
	}
	zerolog.SetGlobalLevel(level)

	config := &pangea.Config{}
	client := authn.New(config)

	secure := hostURL.Scheme == "https"
	proxy := httputil.NewSingleHostReverseProxy(target)
	server := &pangeaProxyServer{
		secret:             []byte(secret),
		authnToken:         authnToken,
		pangeaDomain:       pangeaDomain,
		target:             target,
		hostedPage:         hostedPage,
		authRoute:          authRoute,
		authCookieName:     authCookieName,
		stateCookieName:    stateCookieName,
		redirectCookieName: redirectCookieName,
		client:             client,
		secure:             secure,
		proxy:              proxy,
	}

	if err := http.ListenAndServe(hostURL.String(), server); err != nil {
		log.Fatal().Err(err).Msg("Server Closed")
	}
}

type pangeaProxyServer struct {
	secret             []byte
	authnToken         string
	pangeaDomain       string
	target             *url.URL
	hostedPage         *url.URL
	authRoute          string
	authCookieName     string
	stateCookieName    string
	redirectCookieName string
	client             *authn.AuthN
	secure             bool
	proxy              http.Handler
}

func (p *pangeaProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p.authMiddleware(p.proxy)
}

func (p *pangeaProxyServer) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(p.authCookieName)
		if err != nil {
			log.Debug().Err(err).Msgf("Error while getting cookie with name '%s'", p.authCookieName)
			p.authRedirect(w, r)
			return
		}
		err = decodeCookie(p.secret, cookie)
		if err != nil {
			log.Debug().Err(err).Msg("Error decoding auth cookie")
			p.authRedirect(w, r)
			return
		}

		var t AuthCookie
		if err := json.Unmarshal([]byte(cookie.Value), &t); err != nil {
			log.Error().Err(err).Msg("Failed to parse internal auth token")
			p.authRedirect(w, r)
			return
		}

		if cookie.Expires.Before(time.Now().Add(time.Second * 30)) {
			resp, err := p.client.Client.Session.Refresh(r.Context(), authn.ClientSessionRefreshRequest{
				RefreshToken: t.RefreshToken,
			})
			if err != nil {
				log.Error().Err(err).Msg("Failed to refresh token")
				p.authRedirect(w, r)
				return
			}
			if *resp.Status != "Success" {
				log.Error().Interface("response", resp).Msg("Failed to refresh with response")
				p.authRedirect(w, r)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (p *pangeaProxyServer) authLogin(w http.ResponseWriter, r *http.Request) {

	vars := r.URL.Query()
	code := vars.Get("code")
	state := vars.Get("state")

	if code == "" || state == "" {
		r = r.WithContext(context.WithValue(r.Context(), redirectContextKey, "/"))
		p.authRedirect(w, r)
		return
	}

	stateCookie, err := r.Cookie(p.stateCookieName)
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to grab state cookie with name '%s'", p.stateCookieName)
		p.authRedirect(w, r)
		return
	}

	if decodeCookie(p.secret, stateCookie) != nil {
		p.authRedirect(w, r)
		return
	}

	if stateCookie.Value != state {
		r = r.WithContext(context.WithValue(r.Context(), redirectContextKey, "/"))
		p.authRedirect(w, r)
		return
	}

	redirectCookie, err := r.Cookie(p.redirectCookieName)
	var redirect string
	if err != nil {
		log.Debug().Err(err).Msgf("Failed to get redirect cookie")
		u := *r.URL
		u.Path = "/"
		redirect = u.String()
	} else if err := decodeCookie(p.secret, redirectCookie); err != nil {
		log.Debug().Err(err).Msgf("Failed to decode redirect cookie")
		u := *r.URL
		u.Path = "/"
		redirect = u.String()
	} else {
		redirect = redirectCookie.Value
	}

	// Do Auth
	resp, err := p.client.Client.Userinfo(r.Context(), authn.ClientUserinfoRequest{
		Code: code,
	})

	if err != nil {
		log.Error().Err(err).Msg("Error while fetching userinfo")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, http.StatusText(http.StatusInternalServerError))
		return
	}

	if status := *resp.Status; status != "Success" {
		log.Debug().Interface("response", resp).Msg("Got a bad response from pangea cloud")
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, http.StatusText(http.StatusInternalServerError))
		return
	}

	// Set auth
	expires, err := time.Parse("2006-01-02T15:04:05Z", resp.Result.ActiveToken.Expire)
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse time from pangea cloud")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	ck := AuthCookie{
		ActiveToken:  resp.Result.ActiveToken.Token,
		RefreshToken: resp.Result.RefreshToken.Token,
	}

	b, _ := json.Marshal(ck)
	authCookie := &http.Cookie{
		Name:     p.authCookieName,
		Value:    string(b),
		Expires:  expires,
		Secure:   p.secure,
		HttpOnly: true,
	}
	signCookie(p.secret, authCookie)
	redirectCookie.MaxAge = -1
	stateCookie.MaxAge = -1
	http.SetCookie(w, redirectCookie)
	http.SetCookie(w, stateCookie)
	w.Header().Set("Location", redirect)
	w.WriteHeader(http.StatusFound)
	fmt.Fprint(w, http.StatusText(http.StatusFound))
}

func (p *pangeaProxyServer) authRedirect(w http.ResponseWriter, r *http.Request) {
	state := string(randomBase58(32))

	var finalRedirect string
	if u := r.Context().Value(redirectContextKey); u != "" {
		finalRedirect = r.URL.String()
	} else {
		finalRedirect = r.URL.String()
	}

	authRedirect := *r.URL
	authRedirect.Path = p.authRoute

	var v url.Values
	v.Add("state", state)
	v.Add("redirect_uri", authRedirect.String())

	hp := *p.hostedPage
	hp.RawQuery = v.Encode()

	stateCookie := &http.Cookie{
		Name:     p.stateCookieName,
		Value:    state,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Expires:  time.Now().Add(time.Minute * 5),
	}

	redirectCookie := &http.Cookie{
		Name:     p.redirectCookieName,
		Value:    finalRedirect,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Expires:  time.Now().Add(time.Minute * 5),
	}

	signCookie(p.secret, stateCookie)
	signCookie(p.secret, redirectCookie)
	http.SetCookie(w, stateCookie)
	http.SetCookie(w, redirectCookie)
	w.Header().Set("Location", hp.String())
	w.WriteHeader(http.StatusFound)
	fmt.Fprint(w, http.StatusText(http.StatusFound))
}

func getOrFail(env string) string {
	value := os.Getenv(env)
	if value == "" {
		log.Fatal().Msgf("'%s' is a required environment variable", value)
	}
	return value
}

func getOrFailURL(env string) *url.URL {
	u, err := url.Parse(getOrFail(env))
	if err != nil {
		log.Fatal().Msgf("'%s' must be a valid URL, was not due to: '%s'", env, err)
	}
	return u
}

func getOrDefault(env, defaultValue string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return defaultValue
}
