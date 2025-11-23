INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@example.com', 'admin'),
('alice', 'password', 'alice@example.com', 'user'),
('bob', '123456', 'bob@example.com', 'user');

INSERT INTO comments (author, body) VALUES
('alice', 'Hello everyone!'),
('bob', '<script>alert("stored XSS")</script>');
