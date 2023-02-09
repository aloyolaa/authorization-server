package com.aloyolaa.authorizationserver.service;

import com.aloyolaa.authorizationserver.entity.Client;
import com.aloyolaa.authorizationserver.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class ClientService implements RegisteredClientRepository {
    private final ClientRepository clientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        clientRepository.save(Client.from(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        return Client.from(clientRepository.findById(Long.valueOf(id)).orElseThrow());
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return Client.from(clientRepository.findByClientId(clientId).orElseThrow());
    }
}
