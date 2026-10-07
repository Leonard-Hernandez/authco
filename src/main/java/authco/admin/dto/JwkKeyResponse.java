package authco.admin.dto;

import java.time.Instant;

import authco.jwk.JwkKeyEntity;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "A signing key. The private part is never exposed.")
public record JwkKeyResponse(
        @Schema(description = "Key id; travels as 'kid' in the header of every token it signs") String kid,
        String algorithm,
        @Schema(description = "true: signs new tokens. Only one key is active at a time") boolean active,
        @Schema(description = "When the key was revoked; null while it is still published on the JWKS") Instant revokedAt,
        Instant createdAt) {

    public static JwkKeyResponse from(JwkKeyEntity key) {
        return new JwkKeyResponse(key.getId(), key.getAlgorithm(), key.isActive(), key.getRevokedAt(),
                key.getCreatedAt());
    }
}
