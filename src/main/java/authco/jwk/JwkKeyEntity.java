package authco.jwk;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UuidGenerator;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * A signing key of the authorization server, persisted so that a restart does
 * not invalidate every token already issued.
 *
 * The id doubles as the JWK "kid": it travels in the header of every signed
 * token, and clients use it to pick the matching key out of the JWKS.
 */
@Entity
@Table(name = "jwk_keys")
@Getter
@Setter
@NoArgsConstructor
public class JwkKeyEntity {

	@Id
	@UuidGenerator
	@Column(length = 36)
	private String id;

	// X.509 SubjectPublicKeyInfo, Base64. Public by design: it is served as-is
	// on the JWKS endpoint.
	@Column(name = "public_key", nullable = false, columnDefinition = "TEXT")
	private String publicKey;

	// PKCS#8 private key, AES-GCM encrypted with the master key and Base64
	// encoded. Never leaves the server, never stored in the clear.
	@Column(name = "private_key", nullable = false, columnDefinition = "TEXT")
	private String privateKey;

	@Column(nullable = false, length = 20)
	private String algorithm;

	// true: signs new tokens. false: retired, still published on the JWKS so
	// tokens it already signed keep validating until they expire.
	@Column(nullable = false)
	private boolean active = true;

	@CreationTimestamp
	@Column(name = "created_at", updatable = false)
	private Instant createdAt;
}