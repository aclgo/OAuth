package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/aclgo/OAuth/session"
	"github.com/dghubble/gologin/v2"
	github "github.com/dghubble/gologin/v2/github"
	"github.com/google/uuid"
	OAuth "golang.org/x/oauth2"
	OAuthGit "golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

var (
	ClientIDGithub     = os.Getenv("CLIENT_ID_GITHUB")
	ClientSecretGithub = os.Getenv("CLIENT_SECRET_GITHUB")
	ClientIDGoogle     = os.Getenv("CLIENT_ID_GOOGLE")
	ClientSecretGoogle = os.Getenv("CLIENT_SECRET_GOOGLE")
	control            = session.New(session.DefaultCookieName, time.Hour, time.Hour)
)

var OAuthGoogle = &OAuth.Config{
	ClientID:     ClientIDGoogle,
	ClientSecret: ClientSecretGoogle,
	RedirectURL:  "http://localhost:3000/google/callback",
	Scopes:       []string{"profile", "email", "openid"},
	Endpoint:     google.Endpoint,
}

var OAuthGithub = &OAuth.Config{
	ClientID:     ClientIDGithub,
	ClientSecret: ClientSecretGithub,
	RedirectURL:  "http://localhost:3000/callback",
	Endpoint:     OAuthGit.Endpoint,
}

func Index(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<html><a href="/login">Login</a></html>`)
}

func IndexGoogle(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `<html><a href="/google/login">Login</a></html>`)
}

func Home(w http.ResponseWriter, r *http.Request) {
	id, data, ok := control.Get(r)
	if !ok {
		fmt.Println("user no logged")
		http.Redirect(w, r, "/", http.StatusUnauthorized)
		return
	}

	fmt.Println(id)
	fmt.Println(data)

	fmt.Fprint(w, "home github")
}

func HomeGoogle(w http.ResponseWriter, r *http.Request) {
	id, data, ok := control.Get(r)
	if !ok {
		fmt.Println("user no logged")
		http.Redirect(w, r, "/google", http.StatusUnauthorized)
		return
	}

	fmt.Println(id)
	fmt.Println(data)

	fmt.Fprint(w, "home google")
}

func sessionHandler() http.Handler {
	fn := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		githubUser, err := github.UserFromContext(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		s := session.SessionData{
			Login:     *githubUser.Login,
			ExpiresAt: time.Hour,
		}

		control.Save(w, &s)

		http.Redirect(w, r, "/home", http.StatusTemporaryRedirect)
	})

	return fn
}

func errorHandler() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/login", http.StatusBadRequest)
	}

	return http.HandlerFunc(fn)
}

func googleLogin(w http.ResponseWriter, r *http.Request) {

	url := OAuthGoogle.AuthCodeURL(uuid.New().String())
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func googleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")

	tok, err := OAuthGoogle.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	infoByte, err := googleUserInfo(tok.AccessToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var data map[string]any

	if err := json.Unmarshal(infoByte, &data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	control.Save(w, data["email"].(string))

	http.Redirect(w, r, "/google/home", http.StatusTemporaryRedirect)
}

func googleUserInfo(token string) ([]byte, error) {

	myURL, err := url.Parse("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, fmt.Errorf("url.Parse %w", err)
	}
	params := url.Values{}
	params.Add("access_token", token)
	myURL.RawQuery = params.Encode()

	// fmt.Println(myURL.String())

	req, err := http.NewRequest(http.MethodGet, myURL.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequest %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.DefaultClient.Do %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("io.ReadAll %w", err)
	}

	defer resp.Body.Close()

	return body, nil
}

func main() {

	var (
		port int
	)

	flag.IntVar(&port, "port", 3000, "port running server")
	flag.Parse()

	var i int

	///////////////////GOOGLE//////////////////
	if ClientIDGithub != "" && ClientSecretGithub != "" {
		i++
		http.HandleFunc("/google", IndexGoogle)
		http.HandleFunc("/google/login", googleLogin)
		http.HandleFunc("/google/callback", googleCallback)
		http.HandleFunc("/google/home", Home)
	}

	///////////////////GITHUB//////////////////
	if ClientIDGoogle != "" && ClientSecretGoogle != "" {
		i++

		http.HandleFunc("/", Index)
		http.HandleFunc("/home", HomeGoogle)

		stateConfig := gologin.DefaultCookieConfig

		http.Handle("/login",
			github.StateHandler(
				stateConfig,
				github.LoginHandler(OAuthGithub, nil),
			),
		)

		http.Handle("/callback",
			github.StateHandler(
				stateConfig,
				github.CallbackHandler(OAuthGithub, sessionHandler(), errorHandler()),
			),
		)
	}

	if i < 1 {
		log.Fatal("all env variables github and google empty")
	}

	format := fmt.Sprintf(":%d", port)

	log.Printf("server running port %d\n", port)
	if err := http.ListenAndServe(format, nil); err != nil {
		log.Fatal(err)
	}

}
