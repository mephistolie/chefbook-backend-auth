// Kept at the old command path for build compatibility, but never runs old migrations.
package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/mephistolie/chefbook-backend-auth/internal/config"
	"github.com/mephistolie/chefbook-backend-auth/schema"
	"github.com/peterbourgon/ff/v3"
	"os"
	"time"
)

func main() {
	fs := flag.NewFlagSet("initialize-auth", flag.ContinueOnError)
	initialize := fs.Bool("initialize", false, "explicitly initialize an empty database schema; never migrate existing data")
	c := config.Database{Host: fs.String("db-host", "localhost", "database host"), Port: fs.Int("db-port", 5432, "database port"), User: fs.String("db-user", "", "database user"), Password: fs.String("db-password", "", "database password"), DBName: fs.String("db-name", "", "database name"), SSLMode: fs.String("db-sslmode", "require", "database TLS mode")}
	if e := ff.Parse(fs, os.Args[1:], ff.WithEnvVars()); e != nil {
		os.Exit(2)
	}
	if !*initialize {
		fmt.Fprintln(os.Stderr, "No migrations run. Explicit --initialize is required and only an empty schema is accepted.")
		os.Exit(2)
	}
	db, e := sql.Open("pgx", config.DatabaseURL(c))
	if e != nil {
		fmt.Fprintln(os.Stderr, "database configuration failed")
		os.Exit(1)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if e = schema.Initialize(ctx, db); e != nil {
		fmt.Fprintln(os.Stderr, "initialization refused or failed; existing schema is never converted")
		os.Exit(1)
	}
	fmt.Println("Initial auth schema created")
}
