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
		os.Getenv("DB_NAME"), os.Getenv("DB_PORT"), os.Getenv("DB_HOST"))

	if err != nil {
		exit("app terminated: could not connect to db: " + err.Error())
	}

	rc := auth.NewSessionAuth([]byte(os.Getenv("RESET_PASS_SESS_SECRET")), "resetpass") // todo
	authent := auth.NewSessionAuth([]byte(os.Getenv("AUTH_SECRET")), "default") //todo

	config := api.NewSmtpConfig(os.Getenv("EMAIL_SERVICE_USERNAME"),
		os.Getenv("EMAIL_SERVICE_PASSWORD"), os.Getenv("EMAIL_FROM_FIELD"),
		os.Getenv("SMTP_HOST"), os.Getenv("SMTP_PORT"))


	app, err := api.NewApp(datab, authent, config, rc)
	if err != nil {
		exit("app terminated: could not create new App")
	}

	server, err := api.NewUserServer(app)
	if err != nil {
		exit("app terminated: " + err.Error())
	}

	err = server.Engine.Run(":" + os.Getenv("PORT"))
	if err != nil {
		exit("app terminated")
	}
}

func exit(msg string) {
	fmt.Println(msg)
	os.Exit(1)
}