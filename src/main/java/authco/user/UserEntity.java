package authco.user;

import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import org.hibernate.annotations.UuidGenerator;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class UserEntity {

	@Id
	@UuidGenerator
	@Column(length = 36)
	private String id;

	@Column(nullable = false, unique = true)
	private String email;

	private String name;

	@Column(name = "email_verified", nullable = false)
	private boolean emailVerified = false;

	@CreationTimestamp
	@Column(name = "created_at", updatable = false)
	private Instant createdAt;

	@UpdateTimestamp
	@Column(name = "updated_at")
	private Instant updatedAt;

	@Column(name = "banned_at")
	private Instant bannedAt;

	@Column(name = "ban_reason")
	private String banReason;

	// EAGER on purpose: UserDetailsService needs the authorities at load time,
	// and the role set per user is tiny. LAZY here would risk
	// LazyInitializationException.
	@ManyToMany(fetch = FetchType.EAGER)
	@JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<RoleEntity> roles = new HashSet<>();

	public boolean isBanned() {
		return bannedAt != null;
	}

}
