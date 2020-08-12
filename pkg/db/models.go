package db

type DBUser struct {
	ID                 uint64 `json:"id"`
	Credentials        `json:"credentials"`
	FullName           string `json:"fullname"`
	Phone              string `json:"phone"`
	Address            string `json:"address"`
	SignedUpWithGoogle bool   `json:"registerGoogle"`
}

type User struct {
	ID                 	uint64 `json:"id"`
	Username			string `json:"username"`
	FullName           	string `json:"fullname"`
	Phone              	string `json:"phone"`
	Address            	string `json:"address"`
	SignedUpWithGoogle 	bool   `json:"registerGoogle"`
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func NewUser(username, password, fullname, phone, address string, googleRegistration bool) *DBUser {
	return &DBUser{
		Credentials:        Credentials{Username: username, Password: password},
		FullName:           fullname,
		Phone:              phone,
		Address:            address,
		SignedUpWithGoogle: googleRegistration,
	}
}

type UpdateUserBody struct {
	Username string `json:"username"`
	FullName string `json:"fullname"`
	Phone    string `json:"phone"`
	Address  string `json:"address"`
}

type UpdateUserBodyGoogleSigned struct {
	FullName string `json:"fullname"`
	Phone    string `json:"phone"`
	Address  string `json:"address"`
}

func DBUserToUser(u1 DBUser) *User {
	return &User {
		ID: u1.ID, FullName: u1.FullName, Address: u1.Address, Phone: u1.Phone, SignedUpWithGoogle: u1.SignedUpWithGoogle,
		Username: u1.Username,
	}
}

func DBUserToUpdateUserBody(u1 DBUser) *UpdateUserBody {
	return &UpdateUserBody {
		FullName: u1.FullName, Address: u1.Address, Phone: u1.Phone, Username: u1.Username,
	}
}

type SignUpResponse struct {
	Token string `json:"token"`
	User User `json:"user"`
}

type GoogleResponse struct {
	Id string			`json:"id"`
	Email string		`json:"email"`
	VerifiedEmail bool	`json:"verified_email"`
	Picture string		`json:"picture"`
}