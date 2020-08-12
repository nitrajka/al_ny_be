package main

import (
	"fmt"
	"github.com/nitrajka/al_ny/pkg/api"
	"github.com/nitrajka/al_ny/pkg/auth"
	"github.com/nitrajka/al_ny/pkg/db"
	"os"
)

func main() {

	datab, err := db.NewMysqlDatabase(
		os.Getenv("DB_USERNAME"), os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"), "3306", os.Getenv("DB_HOST"))

	if err != nil {
		exit("app terminated: could not connect to db: " + err.Error())
	}

	//rc, err := api.NewRedisClient(
	//	LoadEnvAddress("REDIS_HOST", "REDIS_PORT", "6379", "localhost"))
	//if err != nil {
	//	exit("app terminated: could not connect to db: " + err.Error())
	//}

	authent1 := auth.NewSessionAuth([]byte("secret")) //todo

	//app, err := api.NewApp(datab, authent)
	config := api.NewSmtpConfig(os.Getenv("EMAIL_SERVICE_USERNAME"),
		os.Getenv("EMAIL_SERVICE_PASSWORD"), os.Getenv("EMAIL_FROM_FIELD"),
		os.Getenv("SMTP_HOST"), os.Getenv("SMTP_PORT"))


	app, err := api.NewApp(datab, authent1, config, nil)
	if err != nil {
		exit("app terminated: could not create new App")
	}

	server, err := api.NewUserServer(app)
	if err != nil {
		exit("app terminated: " + err.Error())
	}

	err = server.Engine.Run(":" + os.Getenv("PORT"))
		//LoadEnvAddress("HOST", "PORT", "8080", "localhost"))
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