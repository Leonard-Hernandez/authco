package authco.user.repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import authco.user.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, String> {

	// Spring Data derives the query from the method name: WHERE email = ?
	// Optional, because a login attempt for an unknown email is a normal case,
	// not an exception. UserDetailsService decides how to react to the empty.
	Optional<UserEntity> findByEmail(String email);

	// Projects only the role names, so the token customizer doesn't load
	// the whole roles collection just to read one column.
	@Query("select r.name from UserEntity u join u.roles r where u.id = :userId")
	Set<String> findRoleNamesByUserId(String userId);

	List<UserEntity> findAllByOrderByCreatedAtDesc();
}
