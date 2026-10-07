package authco.admin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

class AdminCredentialsInitializerTest {

    private AdminCredentialRepository repository;
    private AdminCredentialsInitializer initializer;

    @BeforeEach
    void setUp() {
        repository = mock(AdminCredentialRepository.class);
        initializer = new AdminCredentialsInitializer(repository, new BCryptPasswordEncoder());
    }

    @Test
    @DisplayName("first startup stores the admin with a BCrypt hash, never the clear password")
    void createsAdminOnFirstStartup() {
        when(repository.count()).thenReturn(0L);

        initializer.run(null);

        ArgumentCaptor<AdminCredentialEntity> saved = ArgumentCaptor.forClass(AdminCredentialEntity.class);
        verify(repository).save(saved.capture());
        assertEquals("admin", saved.getValue().getUsername());
        assertTrue(saved.getValue().getPasswordHash().startsWith("$2"), "expected a BCrypt hash");
    }

    @Test
    @DisplayName("later startups leave the existing credentials alone")
    void doesNothingWhenAdminExists() {
        when(repository.count()).thenReturn(1L);

        initializer.run(null);

        verify(repository, never()).save(any());
    }

}
