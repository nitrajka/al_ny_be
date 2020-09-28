## Backend for authentication and authorization of a user

I programmed this backend API as an assignment. The API is capable of signing up a user with Google account or user chosen credentials, where username must be valid email.
As for logging in, user can only log in using the method, he used during sign up. After user is logged in, he is authorized to retrieve and update personal information
from a database. I spend approximately 50 hours with this project (including the frontend part here: https://github.com/nitrajka/al_ny_fe ).

### Routes

`GET /test` - test route, sends code 200 and empty string response

`POST /login`
    - logs in existing user who did not log in through google before
    
    - body: `{username: "user@mail.com", password: "pass"}`
    - response: 
        - success: 
            - code: 200 
            - body: `{
                token: "", 
                user: {id: 1, username: "user@mail.com", fullname: "Full Name", phone: "0900000000", address: "Address", registerGoogle: false}
             }`
        - causes of error: incorrect password, signed up with google before, user does not exists, empty credentials

`POST /login/google`

`POST /logout`
    - logs out logged in user
    
    - body: `{user-ID}`
    - response:
        - success:
            - code: 200
            - body: "some success message"
        - causes of error: non existent user, user not logged in, invalid token, logging out different user

`POST /signup`
    - creates user with given email address as username and password

    - body: `{username: "user@mail.com", password: "pass"}`
    - response:
        - success:
            - code: 201
            - body: `{
                token: "", 
                user: {id: 1, username: "user@mail.com", fullname: "Full Name", phone: "0900000000", address: "Address", registerGoogle: false}
            }`
        - causes of error: invalid body, user exists, already signed up with Google

`GET /user/{id}`
    - retrieves information about user with given ID
    
    - body: empty
    - reponse:
        - success:
            - code: 200
            - body: `user: {id: 1, username: "user@mail.com", fullname: "Full Name", phone: "0900000000", address: "Address", registerGoogle: false}`
        - causes of error: user does not exist, invalid login token, 

`PUT /user/{id}`
    - updates information about user with given ID
    
    - body: `{username: "user@mail.com", fullname: "Full Name 1", phone: "0900000000", address: "Address2"}`
    - response:
        - success:
            - code: 200
            - body: `{id: 1, username: "user@mail.com", fullname: "Full Name 1", phone: "0900000000", address: "Address2", registerGoogle: false}`
        - causes of error: user with ID does not exist, invalid body, invalid log in token, 

`POST /password/reset`
    - validates body, generates reset password token which is part of reset URL (redirect + "/{URL-generated-token}") and sends this URL to given email address where a user can update his/her password
    
    - body: `{email: "mail@mail.com", redirect: "http://froontend-addr.com/redirect"}`
    - response:
        - success:
            - code: 200
            - body: "email sent successfully message"
        - causes of error: invalid body, user does not exist, user signed up with Google, 

`POST /password/reset/validate`
    - validates token sent by frontend, which is the token from previously generated URL in `POST /password/reset`
    
    - body: `{token: "{URL-generaed-token}", email: "mail@mail.com"}`
    - response:
        - success:
            - code: 200
            - body: "success msg"
        - causes of error: token expired, token invalid

`POST /password/renew`
    - validates body, updates a password for a user with given username if token is still valid
    
    - body: `{username: "email@mail.com" ,password: "{new-password}" ,token: "{URL-generated-token}" }`
    - response:
        - success:
            - code: 200
            - body: "success msg"
        - causes of error: invalid body, invalid URL token, URL token expired
            
### Project structure 
- `/pkg`
    - `/api` - API interface definition and implementation
    - `/auth` - authentication interface definition and implementation
    - `/db` - database interface definition and implementation
        - `/scripts` - init script for the database
- `/vendor` - dependencies
    
### What would I do better:

I had a little problem with sessions. I followed many tutorials, which basically explained the same (how to set up 
session in go code) and tried many libraries, such as gorilla/sessions or gin-session. I could not make it work. 
I solved this issue by not only saving the cookie store, but the whole session space (as in this example: 
https://bitbucket.org/nitrajka/al-ny-be/src/5bf9918ae5566eef8653e541ed3d1a83407b6572/pkg/auth/sessionAuth.go#lines-12 ) 
which probably may not be the best solution. Therefore, I would definitely try to make this API more secure.