
#### Run redis inside docker
`docker run --name my-redis-container -p 7001:6379 -d redis`
`docker stop my-redis-container`

[docs](https://www.ionos.com/community/hosting/redis/using-redis-in-docker-containers/)

#### Conenct to redis in container and inspect keys and values
`docker exec -it my-redis-container bash`
`redis-cli -h localhost -p 7001`
`KEYS *`
`TTL <key>`


#### Testing requests
##### Login
`curl  --request POST --data '{"username":"saska","password":"password"}'  http://localhost:8000/login`

##### Create Todo
`curl  --request POST --data '{"userId":1, "title":"Drink"}' --header "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NfdXVpZCI6Ijg2ZDEzZDRlLTNiMGMtNDA5ZC05YWEwLTBiZTkxZmZlMTgxYSIsImF1dGhvcmlzZWQiOnRydWUsImV4cCI6MTU5Njk3Mzg5MiwidXNlcl9pZCI6MX0.lyY0Q6qWf2jCU_I-mp4KLummRTJ6J0weYqA-2lUPdPs"  http://localhost:8000/todo`

##### Logout
`curl  --request POST --header "Authorization: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3NfdXVpZCI6Ijg2ZDEzZDRlLTNiMGMtNDA5ZC05YWEwLTBiZTkxZmZlMTgxYSIsImF1dGhvcmlzZWQiOnRydWUsImV4cCI6MTU5Njk3Mzg5MiwidXNlcl9pZCI6MX0.lyY0Q6qWf2jCU_I-mp4KLummRTJ6J0weYqA-2lUPdPs"  http://localhost:8000/logout`

##### Refresh token
`curl --request POST --data '{"refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1OTc1Nzc3OTIsInJlZnJlc2hfdXVpZCI6IiIsInVzZXJfaWQiOjF9.n82a3mNYCPecYU71UdPcqkmE8-LzzXpmhCzTx9QRIdQ"}' http://localhost:8000/token/refresh`


##### Signup
`curl --request POST --data {"username": "example@mail.com", password:"password"}`