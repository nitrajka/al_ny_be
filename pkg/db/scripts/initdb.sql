CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username varchar(254) UNIQUE NOT NULL,
    password varchar(100) NOT NULL,
    fullname varchar(50) NOT NULL,
    phone varchar(16) NOT NULL,
    address varchar(256) NOT NULL,
    signedUpGoogle BOOLEAN NOT NULL
)