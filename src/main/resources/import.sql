INSERT INTO user (username, password, authority) VALUES ('aloyolaa', '12345', "ROLE_USER");
INSERT INTO user (username, password, authority) VALUES ('admin', '12345', "ROLE_ADMIN");

INSERT INTO client (client_id, secret, scope, auth_method, grant_type, redirect_uri) VALUES ('client', 'secret', 'openid', 'client_secret_basic', 'authorization_code', 'https://springone.io/authorized');