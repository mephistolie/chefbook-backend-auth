package config

import (
	"net"
	"net/url"
	"strconv"
)

// DatabaseURL escapes credentials instead of interpolating a libpq string.
func DatabaseURL(c Database) string {
	mode := "require"
	if c.SSLMode != nil && *c.SSLMode != "" {
		mode = *c.SSLMode
	}
	u := url.URL{Scheme: "postgres", Host: net.JoinHostPort(*c.Host, strconv.Itoa(*c.Port)), Path: "/" + *c.DBName, User: url.UserPassword(*c.User, *c.Password)}
	q := u.Query()
	q.Set("sslmode", mode)
	u.RawQuery = q.Encode()
	return u.String()
}
