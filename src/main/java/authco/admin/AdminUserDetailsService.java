package authco.admin;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import lombok.RequiredArgsConstructor;

// Not a @Component on purpose: as a bean, Spring would register it in the global
// AuthenticationManager. It is wired only into the admin filter chain.
@RequiredArgsConstructor
public class AdminUserDetailsService implements UserDetailsService {

    private final AdminCredentialRepository adminCredentialRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return adminCredentialRepository.findById(username)
                .map(admin -> User.withUsername(admin.getUsername())
                        .password(admin.getPasswordHash())
                        .roles("ADMIN")
                        .build())
                .orElseThrow(() -> new UsernameNotFoundException(username));
    }

}
