INSERT INTO authorities
VALUES (1, 'USER'), (2, 'EDITOR'), (3, 'ADMIN'), (4, 'MODERATOR');

SELECT id, email, authority_id FROM users;