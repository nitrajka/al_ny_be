package db

type Database interface {
	CreateUser(u *DBUser) (*DBUser, error)
	GetUserById(ID uint64) (*DBUser, error)
	UpdateUser(newUser *UpdateUserBody, id uint64) (*DBUser, error)
	UserExistsByCredentials(cred Credentials) (*DBUser, bool, error)
}
