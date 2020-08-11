package main

import (
	"fmt"
	"github.com/nitrajka/al_ny/pkg/db"
	"os"

	"github.com/joho/godotenv"
	"github.com/nitrajka/al_ny/pkg/api"
	"github.com/nitrajka/al_ny/pkg/auth"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		exit("could not load .env variables")
	}

	datab, err := db.NewMysqlDatabase(
		os.Getenv("DB_USERNAME"), os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"), os.Getenv("DB_PORT"))
	if err != nil {
		exit("app terminated: could not connect to db: " + err.Error())
	}

	//authent, err := auth.NewRedisAuthentication(
	//	LoadEnvAddress("REDIS_HOST", "REDIS_PORT", "6379", "localhost"))
	//if err != nil {
	//	exit("app terminated: could not connect to db: " + err.Error())
	//}

	authent1 := auth.NewSessionAuth([]byte("secret")) //todo

	//app, err := api.NewApp(datab, authent)
	app, err := api.NewApp(datab, authent1)
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