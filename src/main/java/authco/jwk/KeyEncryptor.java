package authco.jwk;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class KeyEncryptor {

    private final SecretKeySpec secretKeySpec;

    private final SecureRandom secureRandom = new SecureRandom();

    public KeyEncryptor(@Value("${authco.jwk.master-key}") String masterKey) {
        byte[] keyBytes = Base64.getDecoder().decode(masterKey);

        if (keyBytes.length != 32) {
            throw new IllegalStateException("Master key is truncate");
        }

        this.secretKeySpec = new SecretKeySpec(keyBytes, "AES");
    }

    public String encrypt(byte[] plaintext) {

        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        byte[] ciphertext;

        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmSpec);
            ciphertext = cipher.doFinal(plaintext);

        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage(), e);
        }

        byte[] result = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(ciphertext, 0, result, iv.length, ciphertext.length);
        return Base64.getEncoder().encodeToString(result);
    }

    public byte[] decrypt(String encoded) {
        return null;
    }

}
