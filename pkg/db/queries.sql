-- name: GetUserById :one
SELECT * FROM users
WHERE id = $1 LIMIT 1;

-- name: GetUserByUsername :one
SELECT * FROM users
WHERE username = $1 LIMIT 1;

-- name: ListUsers :many
SELECT * FROM users
ORDER BY id;

-- name: CreateUser :one
INSERT INTO users (
  username, password, fullname, phone, address
) VALUES (
  $1, $2, $3, $4, $5
); SELECT LAST_INSERT_ID();

-- name: UpdateUser :one
UPDATE users
SET username = $1, password = $2, fullname = $3, phone = $4, address = $5
WHERE id = $6;

-- name: DeleteUser :exec
DELETE FROM users
WHERE id = $1;