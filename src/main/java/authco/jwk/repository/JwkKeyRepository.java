package authco.jwk.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import authco.jwk.JwkKeyEntity;

public interface JwkKeyRepository extends JpaRepository<JwkKeyEntity, String> {

	// The key that signs new tokens. Newest first, so a rotation that briefly
	// leaves two rows active still resolves to the one just promoted.
	Optional<JwkKeyEntity> findFirstByActiveTrueOrderByCreatedAtDesc();

	// Every key ever created, revoked ones included. For the admin listing.
	List<JwkKeyEntity> findAllByOrderByCreatedAtDesc();

	// Everything the JWKS endpoint publishes: the active key plus the retired
	// ones still inside their grace period. Revoked keys are left out.
	List<JwkKeyEntity> findAllByRevokedAtIsNullOrderByCreatedAtDesc();

	List<JwkKeyEntity> findAllByActiveTrue();
}