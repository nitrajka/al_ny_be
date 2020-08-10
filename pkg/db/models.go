package db

type User struct {
	ID                 uint64 `json:"id"`
	Credentials        `json:"credentials"`
	FullName           string `json:"fullname"`
	Phone              string `json:"phone"`
	Address            string `json:"address"`
	SignedUpWithGoogle bool   `json:"registerGoogle"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func NewUser(username, password, fullname, phone, address string, googleRegistration bool) *User {
	return &User{
		Credentials:        Credentials{Username: username, Password: password},
		FullName:           fullname,
		Phone:              phone,
		Address:            address,
		SignedUpWithGoogle: googleRegistration,
	}
}

type UpdateUserBody struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
	FullName string `json:"fullname"`
	Phone    string `json:"phone"`
	Address  string `json:"address"`
}