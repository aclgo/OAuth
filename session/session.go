package session

import (
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

const DefaultCookieName = "my-test-oAuth"

type SessionData struct {
	Login     any
	ExpiresAt time.Duration
}

type Control struct {
	CookieName      string
	Sessions        map[string]*SessionData
	ExpirateCookies time.Duration
	ExpirateSession time.Duration
	mu              sync.Mutex
}

func New(ckName string, expCookie time.Duration, expSession time.Duration) *Control {
	return &Control{
		CookieName:      ckName,
		Sessions:        make(map[string]*SessionData),
		ExpirateCookies: expCookie,
		ExpirateSession: expSession,
		mu:              sync.Mutex{},
	}
}

func (c *Control) Get(r *http.Request) (string, *SessionData, bool) {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return "", nil, false
	}

	cookie, err := r.Cookie(c.CookieName)
	if err != nil {
		return "", nil, false
	}

	c.mu.Lock()

	data, ok := c.Sessions[cookie.Value]
	if !ok {
		return "", nil, false
	}

	c.mu.Unlock()

	if time.Now().Before(time.Now().Add(data.ExpiresAt)) {
		delete(c.Sessions, cookie.Value)
		return "", nil, false
	}
	return cookie.Value, data, true
}

func (c *Control) Save(w http.ResponseWriter, data any) {

	id := uuid.New().String()

	cookie := &http.Cookie{
		Name:     c.CookieName,
		Value:    id,
		Path:     "/",
		Expires:  time.Now().Add(c.ExpirateCookies),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteDefaultMode,
	}

	session := SessionData{Login: data}
	session.ExpiresAt = c.ExpirateCookies

	c.mu.Lock()
	defer c.mu.Unlock()

	c.Sessions[id] = &session

	http.SetCookie(w, cookie)
}

func (c *Control) Delete(w http.ResponseWriter, id string) {
	delete(c.Sessions, id)

	cookie := &http.Cookie{
		Name:   c.CookieName,
		MaxAge: -1,
		Value:  "",
	}

	http.SetCookie(w, cookie)
}
