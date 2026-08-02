package authco.jwk;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class KeyEncryptorTest {

    private KeyEncryptor keyEncryptor;

    /**
     * Generates a fresh Base64-encoded 256-bit key, the same way the operator
     * would with {@code openssl rand -base64 32}.
     */
    private static String randomMasterKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return Base64.getEncoder().encodeToString(key);
    }

    @BeforeEach
    void setUp() {
        keyEncryptor = new KeyEncryptor(randomMasterKey());
    }

    @Test
    @DisplayName("decrypt(encrypt(x)) returns the original bytes")
    void roundTripReturnsOriginalPlaintext() {
        byte[] plaintext = "a fake RSA private key".getBytes(StandardCharsets.UTF_8);

        byte[] recovered = keyEncryptor.decrypt(keyEncryptor.encrypt(plaintext));

        assertArrayEquals(plaintext, recovered);
    }

    @Test
    @DisplayName("encrypting the same plaintext twice yields different payloads")
    void encryptUsesAFreshIvOnEveryCall() {
        byte[] plaintext = "same input, every time".getBytes(StandardCharsets.UTF_8);

        String first = keyEncryptor.encrypt(plaintext);
        String second = keyEncryptor.encrypt(plaintext);

        assertNotEquals(first, second, "IV must never repeat under the same key");

        // Both must still decrypt back to the same plaintext.
        assertArrayEquals(plaintext, keyEncryptor.decrypt(first));
        assertArrayEquals(plaintext, keyEncryptor.decrypt(second));
    }

    @Test
    @DisplayName("a single flipped byte is rejected by the GCM tag")
    void tamperedPayloadIsRejected() {
        byte[] plaintext = "tamper with me".getBytes(StandardCharsets.UTF_8);
        byte[] payload = Base64.getDecoder().decode(keyEncryptor.encrypt(plaintext));

        // Flip one bit inside the ciphertext, past the 12-byte IV header.
        payload[payload.length / 2] ^= 0x01;
        String tampered = Base64.getEncoder().encodeToString(payload);

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> keyEncryptor.decrypt(tampered));

        assertTrue(thrown.getMessage().contains("GCM tag mismatch"));
    }

    @Test
    @DisplayName("a payload encrypted under a different master key is rejected")
    void payloadFromAnotherMasterKeyIsRejected() {
        String payload = keyEncryptor.encrypt("secret".getBytes(StandardCharsets.UTF_8));
        KeyEncryptor otherInstance = new KeyEncryptor(randomMasterKey());

        assertThrows(IllegalStateException.class, () -> otherInstance.decrypt(payload));
    }

    @Test
    @DisplayName("a payload shorter than IV + tag is rejected before reaching the cipher")
    void payloadShorterThanIvPlusTagIsRejected() {
        String tooShort = Base64.getEncoder().encodeToString(new byte[27]);

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> keyEncryptor.decrypt(tooShort));

        assertTrue(thrown.getMessage().contains("too short"));
    }

    @Test
    @DisplayName("a non-Base64 payload is reported as a corrupted row")
    void nonBase64PayloadIsRejected() {
        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> keyEncryptor.decrypt("not base64 at all!!"));

        assertTrue(thrown.getMessage().contains("Base64"));
    }

    @Test
    @DisplayName("a master key that is not 32 bytes is rejected at construction")
    void masterKeyOfWrongLengthIsRejected() {
        String shortKey = Base64.getEncoder().encodeToString(new byte[16]);

        IllegalStateException thrown = assertThrows(IllegalStateException.class,
                () -> new KeyEncryptor(shortKey));

        assertTrue(thrown.getMessage().contains("expected 32 bytes"));
    }
}
