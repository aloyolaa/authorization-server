package com.aloyolaa.authorizationserver.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;

@Getter
@Setter
@Entity
@Table(name = "client")
public class Client extends BaseEntity {
    @Column(name = "client_id", nullable = false, length = 45)
    private String clientId;

    @Column(name = "secret", nullable = false, length = 45)
    private String secret;

    @Column(name = "auth_method", nullable = false, length = 45)
    private String authMethod;

    @Column(name = "grant_type", nullable = false, length = 45)
    private String grantType;

    @Column(name = "redirect_uri", nullable = false, length = 200)
    private String redirectUri;

    @Column(name = "scope", nullable = false, length = 45)
    private String scope;

    public static Client from(RegisteredClient registeredClient) {
        Client client = new Client();
        client.setClientId(registeredClient.getClientId());
        client.setSecret(registeredClient.getClientSecret());
        client.setAuthMethod(registeredClient.getClientAuthenticationMethods().stream().findAny().get().getValue());
        client.setGrantType(registeredClient.getAuthorizationGrantTypes().stream().findAny().get().getValue());
        client.setRedirectUri(registeredClient.getRedirectUris().stream().findAny().get()); // NOT CLEAN CODE
        client.setScope(registeredClient.getScopes().stream().findAny().get());
        return client;
    }

    public static RegisteredClient from(Client client) {
        return RegisteredClient.withId(String.valueOf(client.getId()))
                .clientId(client.clientId)
                .clientSecret(client.getSecret())
                .clientAuthenticationMethod(new ClientAuthenticationMethod(client.getAuthMethod()))
                .authorizationGrantType(new AuthorizationGrantType(client.getGrantType()))
                .redirectUri(client.getRedirectUri())
                .scope(client.getScope())
                .tokenSettings(
                        TokenSettings.builder()
                                .accessTokenTimeToLive(Duration.ofHours(24))
                                .build()
                )
                .build();
    }
}