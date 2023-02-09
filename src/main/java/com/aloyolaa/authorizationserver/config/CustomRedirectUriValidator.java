package com.aloyolaa.authorizationserver.config;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.function.Consumer;

public class CustomRedirectUriValidator implements Consumer<OAuth2AuthorizationCodeRequestAuthenticationContext> {
    @Override
    public void accept(OAuth2AuthorizationCodeRequestAuthenticationContext oAuth2AuthorizationCodeRequestAuthenticationContext) {
        OAuth2AuthorizationCodeRequestAuthenticationToken token = oAuth2AuthorizationCodeRequestAuthenticationContext.getAuthentication();
        RegisteredClient registeredClient = oAuth2AuthorizationCodeRequestAuthenticationContext.getRegisteredClient();
        String redirectUri = token.getRedirectUri();
        if (!registeredClient.getRedirectUris().contains(redirectUri)) {
            OAuth2Error oAuth2Error = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST);
            throw new OAuth2AuthorizationCodeRequestAuthenticationException(oAuth2Error, null);
        }
    }
}
