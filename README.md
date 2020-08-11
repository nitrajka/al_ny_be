
#### Run mysql inside docker with create script
```
docker run --name my-cool-sql 
-v /Users/alexandranyitraiova/dev/projects/go/src/github.com/nitrajka/al_ny/pkg/db/scripts:/docker-entrypoint-initdb.d 
-e MYSQL_ROOT_PASSWORD=root-password 
-e MYSQL_DATABASE=cool-database 
-e MYSQL_USER=saska 
-e MYSQL_PASSWORD=password 
--publish 3307:3306 
-d mysql:latest
```

#### Run redis inside docker
`docker run --name my-redis-container -p 7001:6379 -d redis`
`docker stop my-redis-container`

#### Conenct to redis in container and inspect keys and values
`docker exec -it my-redis-container bash`
`redis-cli -h localhost -p 7001`
`KEYS *`
`TTL <key>`


#### Testing requests
##### Login
`curl  --request POST --data '{"username":"saska","password":"password"}'  http://localhost:8000/login`

##### Logout
`curl  --request POST --header "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NfdXVpZCI6Ijg2ZDEzZDRlLTNiMGMtNDA5ZC05YWEwLTBiZTkxZmZlMTgxYSIsImF1dGhvcmlzZWQiOnRydWUsImV4cCI6MTU5Njk3Mzg5MiwidXNlcl9pZCI6MX0.lyY0Q6qWf2jCU_I-mp4KLummRTJ6J0weYqA-2lUPdPs"  http://localhost:8000/logout`

##### Signup
`curl --request POST --data '{"username": "email19@example.com", "password":"password"}' http://localhost:8000/signup`

`curl --request GET --header "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NfdXVpZCI6IjczYzUyYWQyLWFkOTgtNGNiYy1hYmRlLTM3NWE2NjY5YmIxZCIsImF1dGhvcml6ZWQiOnRydWUsInVzZXJfaWQiOjIwfQ.XArp0DU_utRelo-k0rVM_G2IOTqIPyfcHmW2Yrbdq8c", http://localhost:8000/user/20`

`curl --request PUT --header "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NfdXVpZCI6IjczYzUyYWQyLWFkOTgtNGNiYy1hYmRlLTM3NWE2NjY5YmIxZCIsImF1dGhvcml6ZWQiOnRydWUsInVzZXJfaWQiOjIwfQ.XArp0DU_utRelo-k0rVM_G2IOTqIPyfcHmW2Yrbdq8c" --data '{"username": "email19@example.com", "fullname": "saska nyitraiova", "phone": "2763243726", "address": "nove zamky, bernolakovo namestie"}' http://localhost:8000/user/20`