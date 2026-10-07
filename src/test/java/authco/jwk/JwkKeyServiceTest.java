package authco.jwk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import authco.jwk.exception.ActiveKeyRevocationException;
import authco.jwk.exception.JwkKeyNotFoundException;
import authco.jwk.repository.JwkKeyRepository;

class JwkKeyServiceTest {

    private JwkKeyRepository jwkKeyRepository;
    private JwkKeyService jwkKeyService;

    @BeforeEach
    void setUp() {
        byte[] masterKey = new byte[32];
        new SecureRandom().nextBytes(masterKey);

        jwkKeyRepository = mock(JwkKeyRepository.class);
        when(jwkKeyRepository.save(any(JwkKeyEntity.class))).then(returnsFirstArg());
        jwkKeyService = new JwkKeyService(jwkKeyRepository,
                new KeyEncryptor(Base64.getEncoder().encodeToString(masterKey)));
    }

    private static JwkKeyEntity key(String id, boolean active) {
        JwkKeyEntity key = new JwkKeyEntity();
        key.setId(id);
        key.setActive(active);
        return key;
    }

    @Test
    @DisplayName("rotate retires the active key and creates a new active one")
    void rotateRetiresPreviousKey() {
        JwkKeyEntity previous = key("old", true);
        when(jwkKeyRepository.findAllByActiveTrue()).thenReturn(List.of(previous));

        JwkKeyEntity created = jwkKeyService.rotate();

        assertFalse(previous.isActive());
        assertFalse(previous.isRevoked(), "rotation must not revoke: old tokens still need the key");
        assertTrue(created.isActive());
        assertNotNull(created.getPublicKey());
    }

    @Test
    @DisplayName("the active key cannot be revoked")
    void revokeActiveKeyFails() {
        when(jwkKeyRepository.findById("current")).thenReturn(Optional.of(key("current", true)));

        assertThrows(ActiveKeyRevocationException.class, () -> jwkKeyService.revoke("current"));
        verify(jwkKeyRepository, never()).save(any());
    }

    @Test
    @DisplayName("revoking a retired key stamps revokedAt")
    void revokeRetiredKey() {
        when(jwkKeyRepository.findById("old")).thenReturn(Optional.of(key("old", false)));

        JwkKeyEntity revoked = jwkKeyService.revoke("old");

        assertTrue(revoked.isRevoked());
    }

    @Test
    @DisplayName("revoking twice keeps the original revocation time")
    void revokeIsIdempotent() {
        JwkKeyEntity old = key("old", false);
        Instant firstRevocation = Instant.parse("2026-01-01T00:00:00Z");
        old.setRevokedAt(firstRevocation);
        when(jwkKeyRepository.findById("old")).thenReturn(Optional.of(old));

        assertEquals(firstRevocation, jwkKeyService.revoke("old").getRevokedAt());
    }

    @Test
    @DisplayName("revoking an unknown kid raises JwkKeyNotFoundException")
    void revokeUnknownKey() {
        when(jwkKeyRepository.findById("missing")).thenReturn(Optional.empty());

        assertThrows(JwkKeyNotFoundException.class, () -> jwkKeyService.revoke("missing"));
    }

    @Test
    @DisplayName("the published key set leaves revoked keys out")
    void publishedKeysExcludeRevoked() {
        JwkKeyEntity published = jwkKeyService.generateAndSave();
        when(jwkKeyRepository.findAllByRevokedAtIsNullOrderByCreatedAtDesc()).thenReturn(List.of(published));

        assertEquals(1, jwkKeyService.getAllKeys().size());
        verify(jwkKeyRepository, never()).findAllByOrderByCreatedAtDesc();
    }

}
