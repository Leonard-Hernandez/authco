package authco.user.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import authco.user.FederatedIdentityEntity;

public interface FederatedIdentityRepository extends JpaRepository<FederatedIdentityEntity, Long> {

	// The lookup for social login: given (provider, id from the provider),
	// find the local user already linked to it. Matches the uq_provider unique key.
	Optional<FederatedIdentityEntity> findByProviderAndProviderUserId(String provider, String providerUserId);
}
