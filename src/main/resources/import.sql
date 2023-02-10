INSERT INTO user (username, password, enabled) VALUES ('aloyolaa', '12345', true);
INSERT INTO user (username, password, enabled) VALUES ('admin', '12345', true);

INSERT INTO authority (name) VALUES ('ROLE_USER');
INSERT INTO authority (name) VALUES ('ROLE_ADMIN');

INSERT INTO user_authority (user_id, authority_id) VALUES (1, 1);
INSERT INTO user_authority (user_id, authority_id) VALUES (2, 1);
INSERT INTO user_authority (user_id, authority_id) VALUES (2, 2);

INSERT INTO client (client_id, secret, scope, auth_method, grant_type, redirect_uri) VALUES ('client', 'secret', 'openid', 'client_secret_basic', 'authorization_code', 'https://springone.io/authorized');