package authco.jwk;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class KeyEncryptor {

    private final SecretKeySpec secretKeySpec;

    private final SecureRandom secureRandom = new SecureRandom();

    private static final int IV_LENGTH = 12;

    private static final int TAG_LENGTH_BYTES = 16;

    public KeyEncryptor(@Value("${authco.jwk.master-key}") String masterKey) {
        byte[] keyBytes;

        try {
            keyBytes = Base64.getDecoder().decode(masterKey);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid authco.jwk.master-key: is not a base 64", e);
        }

        if (keyBytes.length != 32) {
            throw new IllegalStateException(
                    "Invalid authco.jwk.master-key: expected 32 bytes (AES-256) after Base64 decoding, got "
                            + keyBytes.length);
        }

        this.secretKeySpec = new SecretKeySpec(keyBytes, "AES");
    }

    public String encrypt(byte[] plaintext) {

        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        byte[] ciphertext;

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmSpec);
            ciphertext = cipher.doFinal(plaintext);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to encrypt signing key with AES-GCM", e);
        }

        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(result);
    }

    public byte[] decrypt(String encoded) {
        byte[] decode;
        try {
            decode = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Stored encrypted signing key is not valid Base64 (corrupted row?)", e);
        }
        if (decode.length < IV_LENGTH + TAG_LENGTH_BYTES) {
            throw new IllegalStateException("Encrypted payload too short: got " + decode.length + " bytes, minimum is "
                    + (IV_LENGTH + TAG_LENGTH_BYTES));
        }
        byte[] iv = Arrays.copyOfRange(decode, 0, IV_LENGTH);
        byte[] cipherBytes = Arrays.copyOfRange(decode, IV_LENGTH, decode.length);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        byte[] plaintext;

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, gcmSpec);
            plaintext = cipher.doFinal(cipherBytes);

        } catch (AEADBadTagException e) {
            throw new IllegalStateException(
                    "GCM tag mismatch while decrypting signing key: data was tampered with, or authco.jwk.master-key changed",
                    e);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to decrypt signing key with AES-GCM", e);
        }
        return plaintext;
    }

}
