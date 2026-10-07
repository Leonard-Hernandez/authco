package authco.admin;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Creates the admin login on the very first startup, when the table is empty.
 * The password is printed once and never again: it is not recoverable, only
 * resettable by deleting the row and restarting.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AdminCredentialsInitializer implements ApplicationRunner {

    static final String ADMIN_USERNAME = "admin";

    private static final int PASSWORD_BYTES = 24;

    private final AdminCredentialRepository adminCredentialRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(ApplicationArguments args) {
        if (adminCredentialRepository.count() > 0) {
            return;
        }

        String password = generatePassword();

        AdminCredentialEntity admin = new AdminCredentialEntity();
        admin.setUsername(ADMIN_USERNAME);
        admin.setPasswordHash(passwordEncoder.encode(password));
        adminCredentialRepository.save(admin);

        log.warn("""

                ================================================================
                 authco admin API credentials (shown only once, store them now)
                   username: {}
                   password: {}
                 Lost it? Delete the row in admin_credentials and restart.
                ================================================================""",
                ADMIN_USERNAME, password);
    }

    private String generatePassword() {
        byte[] bytes = new byte[PASSWORD_BYTES];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

}
