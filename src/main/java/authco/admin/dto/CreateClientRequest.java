package authco.admin.dto;

import java.util.Set;

import authco.client.ClientDefinition;
import authco.client.ClientType;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Schema(description = "A trusted client registered by an admin. PKCE is always required.")
public record CreateClientRequest(
        @NotBlank @Pattern(regexp = "[a-z0-9][a-z0-9-]{2,99}") @Schema(example = "finco-web") String clientId,
        @NotBlank @Size(max = 200) @Schema(example = "Finco") String clientName,
        @NotNull @Schema(description = "PUBLIC for SPAs, mobile and CLIs; CONFIDENTIAL for server-side apps") ClientType type,
        @NotEmpty @Schema(example = "[\"http://localhost:4200/auth/callback\"]") Set<String> redirectUris,
        @NotNull @Schema(example = "[\"http://localhost:4200/\"]") Set<String> postLogoutRedirectUris,
        @NotEmpty @Schema(example = "[\"openid\", \"profile\", \"email\"]") Set<String> scopes,
        @Schema(description = "false for your own apps; true for third-party clients", example = "false") boolean requireConsent) {

    public ClientDefinition toDefinition() {
        return new ClientDefinition(clientId, clientName, type, redirectUris, postLogoutRedirectUris, scopes,
                requireConsent);
    }
}
