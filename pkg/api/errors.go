package api

import "fmt"

func NotFoundUserError(key string, value string) string {
	return fmt.Sprintf("User with %v: %v does not exist.\n", key, value)
}

func InvalidBodyError(err error) string {
	return fmt.Sprintf("Invalid body parameters: %v.\n", err)
}

func InvalidLoginType(err error) string {
	return fmt.Sprintf("Use the kind of login as during registration. %v", err)
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
	return fmt.Sprintf("An error occured during password reset: %v", err)
}

func UnauthorizedEmail() string {
	return fmt.Sprintf("For security reasons, this email is not allowed fto reset password. Please contact author to change that.")
}