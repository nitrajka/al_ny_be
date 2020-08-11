package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/nitrajka/al_ny/pkg/auth"
	"github.com/nitrajka/al_ny/pkg/db"
)

type mockDB struct {
	inPlace map[uint64]*db.DBUser
	lastId  uint64
}

func (q *mockDB) CreateUser(u *db.DBUser) (*db.DBUser, error) {
	u.ID = q.lastId + 1
	q.lastId += 1
	u.Password, _ = db.HashPassword(u.Password)
	q.inPlace[u.ID] = u

	return u, nil
}

func (q *mockDB) GetUserById(ID uint64) (*db.DBUser, error) {
	if ID > q.lastId {
		return &db.DBUser{}, errors.New("sorry, such user does not exist")
	}

	return q.inPlace[ID], nil
}

func (q *mockDB) UpdateUser(u *db.UpdateUserBody, userId uint64) (*db.DBUser, error) {
	if userId > q.lastId {
		return &db.DBUser{}, errors.New("sorry, such user does not exist")
	}

	oldUser := q.inPlace[userId]

	newUser := &db.DBUser{
		ID:          oldUser.ID,
		Credentials: db.Credentials{u.Username, oldUser.Password},
		FullName:    u.FullName,
		Address:     u.Address,
		Phone:       u.Phone,
	}

	q.inPlace[newUser.ID] = newUser
	return q.inPlace[newUser.ID], nil
}

func (q *mockDB) UserExistsByCredentials(cred db.Credentials) (*db.DBUser, bool, error) {
	for id := range q.inPlace {
		if q.inPlace[id].Username == cred.Username {
			return q.inPlace[id], true, nil
		}
	}

	return &db.DBUser{}, false, nil
}

func TestAuthWithPassword(t *testing.T) {
	p1, _ := db.HashPassword("password")
	datab := &mockDB{inPlace: map[uint64]*db.DBUser{
		1: {1, db.Credentials{"email@example.com", p1},
			"DBUser Novotny", "09090909", "cool address", false},
		2: {2, db.Credentials{"example@gmail.com", p1},
			"DBUser Pekna", "090909", "very cool address", true},
	}, lastId: 1}

	//aut, err := auth.NewRedisAuthentication("localhost:7001")
	//if err != nil {
	//	t.Errorf("could not connect to redis")
	//}

	aut := auth.NewSessionAuth([]byte("secret-key"))

	ma, err := NewApp(datab, aut)
	if err != nil {
		t.Error("could not create App")
	}

	server, err := NewUserServer(ma)
	if err != nil {
		t.Errorf("could not create server: %v", err)
	}

	t.Run("test successful login + logout", func(t *testing.T) {
		request := newPostLoginRequest(t, "email@example.com", "password")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		userWithToken := getUserWithToken(t, response.Body)


		assertStatus(t, response.Code, http.StatusOK)
		assertUser(t, userWithToken.User, *db.DBUserToUser(*datab.inPlace[1]))

		request = newPostLogoutRequest(t, userWithToken.Token, userWithToken.User.ID)
		response = httptest.NewRecorder()

		server.ServeHTTP(response, request)
		msg := getMessageFromResponse(t, response.Body)

		assertStatus(t, response.Code, http.StatusOK)
		assertMessage(t, msg,"successfully logged out")
	})

	t.Run("test empty login credentials", func(t *testing.T) {
		request := newPostLoginRequest(t, "", "")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		msg := getMessageFromResponse(t, response.Body)
		//token := getTokenFromResponse(t, response.Body)

		assertStatus(t, response.Code, http.StatusBadRequest)
		assertMessage(t, msg, "fields must not be empty")
		//tokenValid()
	})

	t.Run("test user does not exist", func(t *testing.T) {
		request := newPostLoginRequest(t, "emailf@example.com", "password")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		body := getMessageFromResponse(t, response.Body)

		assertStatus(t, response.Code, http.StatusNotFound)
		assertMessage(t, body, "such user does not exist")
	})

	t.Run("test bad password", func(t *testing.T) {
		request := newPostLoginRequest(t, "email@example.com", "passwordd")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		body := getMessageFromResponse(t, response.Body)

		assertStatus(t, response.Code, http.StatusUnauthorized)
		assertMessage(t, body, "incorrect password for this user")
	})

	t.Run("test login with password when previous google registration", func(t *testing.T) {
		request := newPostLoginRequest(t, "example@gmail.com", "password")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		body := getMessageFromResponse(t, response.Body)

		assertStatus(t, response.Code, http.StatusConflict)
		assertMessage(t, body, "please use the kind of login you used while registration")
	})

	t.Run("test signup successful", func(t *testing.T) {
		newMail := "emailik@example.com"
		request := newPostSignupRequest(t, newMail, "password")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		body := getUserWithToken(t, response.Body)
		expected := &db.SignUpResponse{Token:"", User: db.User{
			ID: 2, Username: newMail, FullName: "", Phone: "", Address: "", SignedUpWithGoogle: false}}

		assertStatus(t, response.Code, http.StatusCreated)
		assertSignupResponseBody(t, body, expected)
	})

	t.Run("test signup username already exists", func(t *testing.T) {
		request := newPostSignupRequest(t, "email@example.com", "password")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		body := getMessageFromResponse(t, response.Body)

		assertStatus(t, response.Code, http.StatusConflict)
		assertMessage(t, body, "such username already exists")
	})
}

func TestUsersWithPasswordAuth(t *testing.T) {
	p1, _ := db.HashPassword("password")
	datab := &mockDB{inPlace: map[uint64]*db.DBUser{
		1: {1, db.Credentials{"email@example.com", p1},
			"Petra Novotna", "09090909", "cool address", false},
		2: {2, db.Credentials{"example@gmail.com", p1},
			"Katka Pekna", "090909", "very cool address", true},
		3: {3, db.Credentials{"mail@example.com", p1},
			"Janko Mrkvicka", "090909", "lives with Katka", false},
	}, lastId: 1}

	aut := auth.NewSessionAuth([]byte("secret-key"))

	ma, err := NewApp(datab, aut)
	if err != nil {
		t.Error("could not create App")
	}

	server, err := NewUserServer(ma)
	if err != nil {
		t.Errorf("could not create server: %v", err)
	}

	t.Run("get user successfully", func(t *testing.T) {
		request := newPostLoginRequest(t, "email@example.com", "password")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		userWithToken := getUserWithToken(t, response.Body)

		assertStatus(t, response.Code, http.StatusOK)
		assertUser(t, userWithToken.User, *db.DBUserToUser(*datab.inPlace[1]))


		fmt.Println(userWithToken.Token, userWithToken.User.ID)
		request = newGetUserRequest(t, userWithToken.Token, userWithToken.User.ID)
		response = httptest.NewRecorder()

		server.ServeHTTP(response, request)
		user := getUserFromResponse(t, response.Body)

		assertStatus(t, response.Code, http.StatusOK)
		assertUser(t, *db.DBUserToUser(*datab.inPlace[1]), *user)

	})

	t.Run("update user successfully", func(t *testing.T) {
		request := newPostLoginRequest(t, "email@example.com", "password")
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		userWithToken := getUserWithToken(t, response.Body)

		assertStatus(t, response.Code, http.StatusOK)
		assertUser(t, userWithToken.User, *db.DBUserToUser(*datab.inPlace[1]))


		dbuser := datab.inPlace[1]
		user := &db.UpdateUserBody{
			Username: dbuser.Username,
			FullName: "Petra Novakova",
			Phone:    dbuser.Phone,
			Address:  dbuser.Address,
		}

		request = newPutUserRequest(t, user, userWithToken.Token, dbuser.ID)
		response = httptest.NewRecorder()

		server.ServeHTTP(response, request)
		newUser := getUserFromResponse(t, response.Body)

		expected := db.DBUserToUser(*dbuser)
		expected.FullName = "Petra Novakova"

		assertStatus(t, response.Code, http.StatusOK)
		assertUser(t, *newUser, *expected)
	})

	invalidToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NfdXVpZCI6Ijg2ZDEzZDRlLTNiMGMtNDA5ZC05YWEwLTBiZTkxZmZlMTgxYSIsImF1dGhvcmlzZWQiOnRydWUsImV4cCI6MTU5Njk3Mzg5MiwidXNlcl9pZCI6MX0.lyY0Q6qWf2jCU_I-mp4KLummRTJ6J0weYqA-2lUPdPs"

	t.Run("cannot get user without auth", func(t *testing.T) {
		request := newGetUserRequest(t, invalidToken, 1)
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		msg := getMessageFromResponse(t, response.Body)

		assertStatus(t, response.Code, http.StatusUnauthorized)
		assertMessage(t, msg, "unauthorized")
	})

	t.Run("cannot update user without auth", func(t *testing.T) {
		dbuser := datab.inPlace[1]
		user := &db.UpdateUserBody{
			Username: dbuser.Username,
			FullName: dbuser.FullName,
			Phone:    dbuser.Phone,
			Address:  dbuser.Address,
		}

		user.FullName = "Petra Novakova"
		request := newPutUserRequest(t, user, invalidToken, dbuser.ID)
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		msg := getMessageFromResponse(t, response.Body)

		assertStatus(t, response.Code, http.StatusUnauthorized)
		assertMessage(t, msg, "unauthorized")
	})

	t.Run("cannot update user without auth", func(t *testing.T) {
		dbuser := datab.inPlace[3]
		user := &db.UpdateUserBody{
			Username: dbuser.Username,
			FullName: dbuser.FullName,
			Phone:    dbuser.Phone,
			Address:  dbuser.Address,
		}
		user.FullName = "Petra Novakova"
		request := newPutUserRequest(t, user, invalidToken, dbuser.ID)
		response := httptest.NewRecorder()

		server.ServeHTTP(response, request)
		msg := getMessageFromResponse(t, response.Body)

		assertStatus(t, response.Code, http.StatusUnauthorized)
		assertMessage(t, msg, "signature is invalid")
	})
}

//----------------------------create request helpers--------------------------------

func newPostLoginRequest(t *testing.T, username, password string) *http.Request {
	req, err := http.NewRequest(
		http.MethodPost,
		"/login",
		strings.NewReader(`{"username": "`+username+`", "password": "`+password+`"}`))
	if err != nil {
		t.Errorf("something went wrong creating a request: %v", err)
	}
	return req
}

func newPostLogoutRequest(t *testing.T, token string, id uint64) *http.Request {
	req, err := http.NewRequest(http.MethodPost, "/logout", strings.NewReader(fmt.Sprintf(`%d`, id)))
	if err != nil {
		t.Errorf("something went wrong creating a request: %v", err)
		return nil
	}

	req.Header.Add("Authorization", token)

	return req
}

func newPostSignupRequest(t *testing.T, username, password string) *http.Request {
	req, err := http.NewRequest(
		http.MethodPost,
		"/signup",
		strings.NewReader(`{"username": "`+username+`", "password": "`+password+`"}`))
	if err != nil {
		t.Errorf("something went wrong creating a request: %v", err)
	}
	return req
}

func newGetUserRequest(t *testing.T, token string, userId uint64) *http.Request {
	path := "/user/" + fmt.Sprintf(`%d`, userId)
	req, err := http.NewRequest(http.MethodGet, path, nil)
	if err != nil {
		t.Errorf("something went wrong creating a request: %v", err)
	}

	req.Header.Add("Authorization", token)
	return req
}

func newPutUserRequest(t *testing.T, u *db.UpdateUserBody, token string, userId uint64) *http.Request {
	path := "/user/" + fmt.Sprintf(`%d`, userId)
	req, err := http.NewRequest(
		http.MethodPut,
		path,
		strings.NewReader(
			fmt.Sprintf(`{"address": "%s", "phone": "%s", "fullname": "%s", "username": "%s" }`, u.Address, u.Phone, u.FullName, u.Username)))
	if err != nil {
		t.Errorf("something went wrong creating a request: %v", err)
	}

	req.Header.Add("Authorization", token)

	return req
}

//------------------------------decode response helpers--------------------------------

func getUserWithToken(t *testing.T, buff *bytes.Buffer) *db.SignUpResponse {
	t.Helper()

	var resp *db.SignUpResponse

	err := json.NewDecoder(buff).Decode(&resp)
	if err != nil {
		t.Errorf("signup response incorrect: %v", err.Error())
		return nil
	}

	return resp
}

func getTokenFromResponse(t *testing.T, resp *bytes.Buffer) string {
	t.Helper()

	var sr *db.SignUpResponse
	err := json.NewDecoder(resp).Decode(&sr)
	if err != nil {
		t.Error("error while decoding token from response")
	}

	return sr.Token
}

func getMessageFromResponse(t *testing.T, resp *bytes.Buffer) (msg string) {
	t.Helper()

	err := json.NewDecoder(resp).Decode(&msg)
	if err != nil {
		t.Errorf("error while decoding response message: %v", err)
	}

	return
}

func getUserFromResponse(t *testing.T, resp *bytes.Buffer) (user *db.User) {
	t.Helper()

	err := json.NewDecoder(resp).Decode(&user)
	if err != nil {
		t.Errorf("error while decoding DBUser in response: %v", err)
	}

	return
}

//------------------------------------assertion helpers----------------------------------------

func assertStatus(t *testing.T, actual, expected int) {
	t.Helper()
	if actual != expected {
		t.Errorf("did not get correct status, actual %d, expected %d", actual, expected)
	}
}

func assertMessage(t *testing.T, actual, expected string) {
	t.Helper()
	if actual != expected {
		t.Errorf("msg not right: actual %s, expected %s", actual, expected)
	}
}

func assertSignupResponseBody(t *testing.T, actual, expected *db.SignUpResponse) {
	t.Helper()

	assertUser(t, actual.User, expected.User)
}

func assertUser(t *testing.T, actual, expected db.User) {
	t.Helper()

	if actual.ID != expected.ID ||
		actual.FullName != expected.FullName ||
		actual.Address != expected.Address ||
		actual.Phone != expected.Phone ||
		actual.Username != expected.Username ||
		actual.SignedUpWithGoogle != expected.SignedUpWithGoogle {
		t.Errorf("user does not match: actual: %v, expected: %v", actual, expected)
	}
}