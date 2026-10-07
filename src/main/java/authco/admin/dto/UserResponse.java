package authco.admin.dto;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

import authco.user.RoleEntity;
import authco.user.UserEntity;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "An authco user")
public record UserResponse(
        @Schema(description = "authco user id; the 'sub' of every token issued to this user") String id,
        String email,
        String name,
        boolean emailVerified,
        @Schema(description = "When the user was banned; null if not banned") Instant bannedAt,
        String banReason,
        @Schema(description = "Role names, granted as access token scopes", example = "[\"finco:premium\"]") Set<String> roles,
        Instant createdAt) {

    public static UserResponse from(UserEntity user) {
        return new UserResponse(user.getId(), user.getEmail(), user.getName(), user.isEmailVerified(),
                user.getBannedAt(), user.getBanReason(),
                user.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toSet()),
                user.getCreatedAt());
    }
}
