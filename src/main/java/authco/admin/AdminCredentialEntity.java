package authco.admin;

import java.time.Instant;

import org.hibernate.annotations.CreationTimestamp;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * The login for the admin API. Only the BCrypt hash is persisted; the clear
 * password exists once, in the log line printed when it is generated.
 */
@Entity
@Table(name = "admin_credentials")
@Getter
@Setter
@NoArgsConstructor
public class AdminCredentialEntity {

	@Id
	@Column(length = 50)
	private String username;

	@Column(name = "password_hash", nullable = false, length = 100)
	private String passwordHash;

	@CreationTimestamp
	@Column(name = "created_at", updatable = false)
	private Instant createdAt;
}
