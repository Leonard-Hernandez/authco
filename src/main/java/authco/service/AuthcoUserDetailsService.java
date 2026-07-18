package authco.service;

import java.util.Optional;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import authco.user.UserEntity;
import authco.user.repository.UserRepository;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class AuthcoUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<UserEntity> userOptional = userRepository.findByEmail(username);

        UserEntity user = userOptional.orElseThrow(() -> new IllegalArgumentException("User Not Found"));

        return User.builder().username(user.getUsername()).password(user.getPassword())
                .authorities(user.getAuthorities()).build();
    }

}
