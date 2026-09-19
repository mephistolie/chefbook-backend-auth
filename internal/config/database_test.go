package config

import (
	"net/url"
	"testing"
)

func TestDatabaseCredentialsAreEscaped(t *testing.T) {
	host, user, password, name, mode := "localhost", "user name", "x' @?sslmode=disable", "auth", "require"
	port := 5432
	raw := DatabaseURL(Database{Host: &host, Port: &port, User: &user, Password: &password, DBName: &name, SSLMode: &mode})
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := parsed.User.Password()
	if got != password || parsed.User.Username() != user || parsed.Query().Get("sslmode") != "require" {
		t.Fatal("credentials altered connection options")
	}
}
