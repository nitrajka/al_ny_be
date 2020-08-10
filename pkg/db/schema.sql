CREATE TABLE users (
    id INTEGER PRIMARY KEY NOT NULL,
    username varchar(254) UNIQUE NOT NULL,
    password varchar(30) NOT NULL,
    fullname varchar(50) NOT NULL,
    phone varchar(16) NOT NULL,
    address varchar(256) NOT NULL
)