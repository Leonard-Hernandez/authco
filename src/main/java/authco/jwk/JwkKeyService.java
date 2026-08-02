package authco.jwk;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import org.springframework.stereotype.Service;

import com.nimbusds.jose.jwk.RSAKey;

import authco.jwk.repository.JwkKeyRepository;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class JwkKeyService {

    private final JwkKeyRepository jwkKeyRepository;

    private final KeyEncryptor keyEncryptor;

    public JwkKeyEntity generateAndSave() {

        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("The key pair generator algorithm is not valid in key", ex);
        }

        JwkKeyEntity jwkKeyEntity = new JwkKeyEntity();
        jwkKeyEntity.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        jwkKeyEntity.setPrivateKey(keyEncryptor.encrypt(keyPair.getPrivate().getEncoded()));
        jwkKeyEntity.setAlgorithm("RS256");
        jwkKeyEntity.setActive(true);

        return jwkKeyRepository.save(jwkKeyEntity);
    }

    public RSAKey toRsaKey(JwkKeyEntity entity) {
        byte[] decodePublicKey = Base64.getDecoder().decode(entity.getPublicKey());
        byte[] decodePrivateKey = keyEncryptor.decrypt(entity.getPrivateKey());

        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(decodePublicKey);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(decodePrivateKey);

        RSAPublicKey publicKey;
        RSAPrivateKey privateKey;

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            publicKey = (RSAPublicKey) keyFactory.generatePublic(x509EncodedKeySpec);
            privateKey = (RSAPrivateKey) keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("The key factory algorithm is not valid in key " + entity.getId(), e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException("The key spec is invalid in key " + entity.getId(), e);
        }

        return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(entity.getId()).build();
    }

}
