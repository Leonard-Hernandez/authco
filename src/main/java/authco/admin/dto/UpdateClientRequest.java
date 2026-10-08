package authco.admin.dto;

import java.util.Set;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

@Schema(description = "Replaces these fields; the client id and type cannot change")
public record UpdateClientRequest(
        @NotBlank @Size(max = 200) String clientName,
        @NotEmpty Set<String> redirectUris,
        @NotNull Set<String> postLogoutRedirectUris,
        @NotEmpty Set<String> scopes,
        boolean requireConsent) {
}
