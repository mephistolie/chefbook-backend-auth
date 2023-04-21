package main

import (
	"flag"
	migrateSql "github.com/mephistolie/chefbook-backend-common/migrate/sql"
	"github.com/peterbourgon/ff/v3"
	"os"
)

const migrationsPath = "migrations/sql"

func main() {
	fs := flag.NewFlagSet("", flag.ContinueOnError)
	params := migrateSql.Params{
		Driver:   "pgx",
		Host:     fs.String("db-host", "localhost", "database host"),
		Port:     fs.Int("db-port", 5432, "database port"),
		User:     fs.String("db-user", "", "database user name"),
		Password: fs.String("db-password", "", "database user password"),
		DB:       fs.String("db-name", "", "service database name"),
	}
	if err := ff.Parse(fs, os.Args[1:], ff.WithEnvVars()); err != nil {
		panic(err)
	}
	migrateSql.Postgres(params, migrationsPath)
}
