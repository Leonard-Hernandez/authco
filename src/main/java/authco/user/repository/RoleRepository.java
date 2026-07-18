package authco.user.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import authco.user.RoleEntity;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

	// Needed to attach the seeded 'USER' / 'PREMIUM' / 'ADMIN' rows to a new user
	// instead of inserting a duplicate role.
	Optional<RoleEntity> findByName(String name);
}
