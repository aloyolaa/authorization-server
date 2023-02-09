package com.aloyolaa.authorizationserver.service;

import com.aloyolaa.authorizationserver.entity.User;
import com.aloyolaa.authorizationserver.model.SecurityUser;
import com.aloyolaa.authorizationserver.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByUsername(username);
        return user.map(SecurityUser::new).orElseThrow(() -> new UsernameNotFoundException("User with username " + username + " does not exist"));
    }
}
