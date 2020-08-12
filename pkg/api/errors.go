package api

import "fmt"

func NotFoundUserError(err error) string {
	return fmt.Sprintf("User with id: %v does not exist.\n", err)
}

func InvalidBodyError(err error) string {
	return fmt.Sprintf("Could not create user, invalid body parameters: %v.\n", err)
}

func InvalidLoginType(err error) string {
	return fmt.Sprintf("Use the kind of login as during registration.")
}

func InternalServerError(err error) string {
	return fmt.Sprintf("Oops, something went wrong, try later: %v.\n", err)
}

func IncorrectPasswordError(err error) string {
	return fmt.Sprintf("Incorrect password for user %v\n", err.Error())
}

func UnauthorizedError(err error) string {
	return fmt.Sprintf("Unauthorized action. Must provide valid credentials. Please, log in correctly. %v\n", err)
}

func UserAlreadyExists(err error) string {
	return fmt.Sprintf("User with username %v already exists.", err.Error())
}

func InvalidPathParam(err error) string {
	return fmt.Sprintf("Please, provide valid path param. %v\n", err.Error())
}

func ResetPasswordError(err error) string {
	return fmt.Sprintf("error occured durin password reset: %v", err)
}