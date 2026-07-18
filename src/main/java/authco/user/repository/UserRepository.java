package authco.user.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import authco.user.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, String> {

	// Spring Data derives the query from the method name: WHERE email = ?
	// Optional, because a login attempt for an unknown email is a normal case,
	// not an exception. UserDetailsService decides how to react to the empty.
	Optional<UserEntity> findByEmail(String email);
}
