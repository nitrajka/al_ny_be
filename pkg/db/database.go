package db

import (
	"database/sql"
	"errors"

	_ "github.com/go-sql-driver/mysql"
)

type Queries struct {
	inPlace map[uint64]*DBUser
	lastId  uint64
	*sql.DB
}

type Database interface {
	CreateUser(u *DBUser) (*DBUser, error)
	GetUserById(ID uint64) (*DBUser, error)
	UpdateUser(newUser *UpdateUserBody) (*DBUser, error)
	UserExistsByCredentials(cred Credentials) (*DBUser, bool)
}

func NewDatabase(username, password, dbname string) (Database, error) {
	db, _ := sql.Open("mysql", username+":"+password+"@/"+dbname)
	//if err != nil {
	//	return &Queries{}, err
	//}

	return &Queries{inPlace: make(map[uint64]*DBUser), DB: db}, nil
}

func (q *Queries) CreateUser(u *DBUser) (*DBUser, error) {
	u.ID = q.lastId + 1
	q.lastId += 1
	q.inPlace[u.ID] = u

	return u, nil
}

func (q *Queries) GetUserById(ID uint64) (*DBUser, error) {
	if ID > q.lastId {
		return &DBUser{}, errors.New("sorry, such user does not exist")
	}

	return q.inPlace[ID], nil
}

func (q *Queries) UpdateUser(u *UpdateUserBody) (*DBUser, error) {
	if u.ID > q.lastId {
		return &DBUser{}, errors.New("sorry, such user does not exist")
	}

	oldUser := q.inPlace[u.ID]

	newUser := &DBUser{
		ID:          oldUser.ID,
		Credentials: Credentials{u.Username, oldUser.Password},
		FullName:    u.FullName,
		Address:     u.Address,
		Phone:       u.Phone,
	}

	q.inPlace[newUser.ID] = newUser
	return q.inPlace[newUser.ID], nil
}

func (q *Queries) UserExistsByCredentials(cred Credentials) (*DBUser, bool) {
	for id := range q.inPlace {
		if q.inPlace[id].Username == cred.Username {
			return q.inPlace[id], true
		}
	}

	return &DBUser{}, false
}