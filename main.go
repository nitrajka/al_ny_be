package main

import (
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/nitrajka/al_ny/pkg/api"
	"github.com/nitrajka/al_ny/pkg/auth"
	"github.com/nitrajka/al_ny/pkg/db"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		exit("could not load .env variables")
	}

	datab, err := db.NewDatabase("db_user", "db_password", "db_name")
	if err != nil {
		exit("app terminated: could not connect to db: " + err.Error())
	}

	auth, err := auth.NewAuthentication(
		LoadEnvAddress("REDIS_HOST", "REDIS_PORT", "6379", "localhost"))
	if err != nil {
		exit("app terminated: could not connect to db: " + err.Error())
	}

	app, err := api.NewApp(datab, auth)
	if err != nil {
		exit("app terminated: could not create new App")
	}

	server, err := api.NewUserServer(app)
	if err != nil {
		exit("app terminated: " + err.Error())
	}

	err = server.Engine.Run(
		LoadEnvAddress("HOST", "PORT", "8080", "localhost"))
	if err != nil {
		exit("app terminated")
	}
}

func LoadEnvAddress(hostEnvName, portEnvName, defaultPort, defaultHost string) string {
	host := os.Getenv(hostEnvName)
	port := os.Getenv(portEnvName)

	if host == "" {
		host = defaultHost
	}

	if port == "" {
		port = defaultPort
	}

	return host + ":" + port
}

func exit(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}