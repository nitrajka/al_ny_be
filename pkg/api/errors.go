package api

import "fmt"

func NotFoundUserError(key, value string) string {
	return fmt.Sprintf("User with %v: %v does not exist.\n", key, value)
}

func InvalidBodyError(err error) string {
	return fmt.Sprintf("Invalid body parameters: %v.\n", err)
}

func InvalidLoginType(err error) string {
	return fmt.Sprintf("Use the kind of login as during registration. %v", err)
}

func InternalServerError(err error) string {
	return fmt.Sprintf("Oops, something went wrong, try later: %v.", err)
}

func IncorrectPasswordError(user string) string {
	return fmt.Sprintf("Incorrect password for user %v.", user)
}

func UnauthorizedError(err error) string {
	return fmt.Sprintf("Unauthorized action. Must provide valid credentials. Please, log in correctly. %v\n", err)
}

func UserAlreadyExists(username string) string {
	return fmt.Sprintf("User with username %v already exists.", username)
}

func InvalidPathParam(err error) string {
	return fmt.Sprintf("Please, provide valid path parameter. %v\n", err.Error())
}

func ResetPasswordError(err error) string {
	return fmt.Sprintf("An error occurred during password reset: %v", err)
}

func UnauthorizedEmail() string {
	return "For security reasons, this email is not allowed fto reset password. Please contact author to change that."
}