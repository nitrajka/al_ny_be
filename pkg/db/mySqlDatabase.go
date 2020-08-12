package db

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"golang.org/x/crypto/bcrypt"
)

type dbClient struct {
	mysql *sql.DB
}

func NewMysqlDatabase(username, password, dbname, dbport string) (Database, error) {
	db, err := sql.Open("mysql", username+":"+password+"@tcp(127.0.0.1:"+dbport+")/"+dbname)
	if err != nil {
		return nil, err
	}

	return &dbClient{db}, err
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

type mysqlUser struct {
	id int64
	username string
	password string
	fullname string
	phone string
	address string
	signedUpGoogle bool
}

func MysqlUserToDBUser(u *mysqlUser) *DBUser {
	res := &DBUser{
		ID:                 uint64(u.id),
		Credentials:        Credentials{Username: u.username, Password: u.password},
		FullName:           u.fullname,
		Phone:              u.phone,
		Address:            u.address,
		SignedUpWithGoogle: u.signedUpGoogle,
	}

	return res
}

func (d *dbClient) CreateUser(u *DBUser) (*DBUser, error) {
	query, err := d.mysql.Prepare("INSERT INTO users (username, password, fullname, phone, address, signedUpGoogle) " +
		"VALUES( ?, ?, ?, ?, ?, ? )")
	if err != nil {
		return &DBUser{}, err
	}

	hashedP, err := HashPassword(u.Password)
	if err != nil {
		return &DBUser{}, err
	}

	res, err := query.Exec(u.Username, hashedP, u.FullName, u.Phone, u.Address, u.SignedUpWithGoogle)
	if err != nil {
		return &DBUser{}, err
	}

	id, err := res.LastInsertId()
	u.ID = uint64(id)
	u.Credentials.Password = hashedP

	return u, nil
}

func (d *dbClient) GetUserById(ID uint64) (*DBUser, error) {
	query, err := d.mysql.Prepare("SELECT id, username, password, fullname, phone, address, signedUpGoogle from users WHERE id = ?")
	if err != nil {
		return &DBUser{}, err
	}

	var id int
	var username string
	var password string
	var fullname string
	var phone string
	var address string
	var signedUpWithGoogle bool

	err = query.QueryRow(ID).Scan(&id, &username, &password, &fullname, &phone, &address, &signedUpWithGoogle)
	if err != nil {
		return &DBUser{}, err
	}

	return &DBUser{
		ID:                 uint64(id),
		Credentials:        Credentials{Username: username, Password: password},
		FullName:           fullname,
		Phone:              phone,
		Address:            address,
		SignedUpWithGoogle: signedUpWithGoogle,
	}, nil
}

func (d *dbClient) UpdateUser(u *UpdateUserBody, id uint64) (*DBUser, error) { // password?
	query, err := d.mysql.Prepare("UPDATE users SET username = ?, fullname = ?, phone = ?, address = ? WHERE id = ?")

	_, err = query.Exec(u.Username, u.FullName, u.Phone, u.Address, id)
	if err != nil {
		return &DBUser{}, err
	}

	dbUser, err := d.GetUserById(id)
	if err != nil {
		return &DBUser{}, err
	}

	return dbUser, nil
}

func (d *dbClient) UserExistsByCredentials(cred Credentials) (*DBUser, bool, error) {
	query, err := d.mysql.Prepare("SELECT id, username, password, fullname, phone, address, signedUpGoogle from users WHERE username = ?")
	if err != nil {
		return &DBUser{}, false, err
	}

	var id int
	var username string
	var password string
	var fullname string
	var phone string
	var address string
	var signedUpWithGoogle bool

	err = query.QueryRow(cred.Username).Scan(&id, &username, &password, &fullname, &phone, &address, &signedUpWithGoogle)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return &DBUser{}, false, nil
		}
		return &DBUser{}, false, err
	}

	return &DBUser{
		ID:                 uint64(id),
		Credentials:        Credentials{Username: username, Password: password},
		FullName:           fullname,
		Phone:              phone,
		Address:            address,
		SignedUpWithGoogle: signedUpWithGoogle,
	}, true, nil
}

func (d *dbClient) ResetPassword(cred Credentials) error {
	query, err := d.mysql.Prepare("UPDATE users SET password = ? WHERE username = ?")

	hashedP, err := HashPassword(cred.Password)
	if err != nil {
		return err
	}

	_, err = query.Exec(hashedP, cred.Username)
	if err != nil {
		return err
	}

	return nil
}