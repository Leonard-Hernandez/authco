package authco.user.repository;

import java.util.Optional;
import java.util.Set;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import authco.user.FederatedIdentityEntity;

public interface FederatedIdentityRepository extends JpaRepository<FederatedIdentityEntity, Long> {

	// The lookup for social login: given (provider, id from the provider),
	// find the local user already linked to it. Matches the uq_provider unique key.
	@EntityGraph(attributePaths = { "user" })
	Optional<FederatedIdentityEntity> findByProviderAndProviderUserId(String provider, String providerUserId);

	@Query("select r.name from FederatedIdentityEntity f join f.user u join u.roles r " +
			"where f.provider = :provider and f.providerUserId = :providerUserId")
	Set<String> findRoleNamesByFederatedIdentity(String provider, String providerUserId);
}
