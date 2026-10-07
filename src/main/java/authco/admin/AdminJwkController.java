package authco.admin;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import authco.admin.dto.JwkKeyResponse;
import authco.jwk.JwkKeyService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/admin/jwks")
@RequiredArgsConstructor
@Tag(name = "Signing keys", description = "Rotate and revoke the keys that sign authco tokens")
public class AdminJwkController {

    private final JwkKeyService jwkKeyService;

    @GetMapping
    @Operation(summary = "List signing keys", description = "Newest first, revoked keys included.")
    public List<JwkKeyResponse> list() {
        return jwkKeyService.listKeys().stream().map(JwkKeyResponse::from).toList();
    }

    @PostMapping("/rotate")
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Rotate the signing key", description = """
            Creates a new active key that signs every token from now on. The
            previous key is retired, not revoked: it stays on the JWKS so tokens
            it already signed keep validating until they expire.""")
    public JwkKeyResponse rotate() {
        return JwkKeyResponse.from(jwkKeyService.rotate());
    }

    @PostMapping("/{kid}/revoke")
    @Operation(summary = "Revoke (deny) a signing key", description = """
            Removes the key from the JWKS: every token it signed stops validating
            immediately. Use it when a key may be compromised. The active key
            cannot be revoked; rotate first, then revoke the retired key.""")
    @ApiResponse(responseCode = "404", description = "No key with that kid")
    @ApiResponse(responseCode = "409", description = "The key is the active signing key")
    public JwkKeyResponse revoke(@PathVariable String kid) {
        return JwkKeyResponse.from(jwkKeyService.revoke(kid));
    }

}
