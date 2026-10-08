package authco.admin;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import authco.admin.dto.ClientResponse;
import authco.admin.dto.CreateClientRequest;
import authco.admin.dto.CreatedClientResponse;
import authco.admin.dto.UpdateClientRequest;
import authco.client.ClientAdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/admin/clients")
@RequiredArgsConstructor
@Tag(name = "Clients", description = "Register the trusted applications that log users in through authco")
public class AdminClientController {

    private final ClientAdminService clientAdminService;

    @GetMapping
    @Operation(summary = "List clients", description = "Newest first; includes clients created through DCR.")
    public List<ClientResponse> list() {
        return clientAdminService.list().stream().map(ClientResponse::from).toList();
    }

    @GetMapping("/{clientId}")
    @Operation(summary = "Get a client")
    @ApiResponse(responseCode = "404", description = "No client with that client_id")
    public ClientResponse get(@PathVariable String clientId) {
        return ClientResponse.from(clientAdminService.get(clientId));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(summary = "Register a client", description = """
            PKCE is always required and access tokens last 15 minutes. CONFIDENTIAL
            clients get a generated secret, returned only in this response. Redirect
            URIs must be https, except http on localhost for development. Scopes are
            limited to openid, profile and email: role scopes come from the user.""")
    @ApiResponse(responseCode = "400", description = "Invalid redirect URI or scope")
    @ApiResponse(responseCode = "409", description = "The client_id is already taken")
    public CreatedClientResponse create(@Valid @RequestBody CreateClientRequest request) {
        return CreatedClientResponse.from(clientAdminService.create(request.toDefinition()));
    }

    @PutMapping("/{clientId}")
    @Operation(summary = "Update a client", description = "Replaces name, redirect URIs, scopes and consent policy.")
    @ApiResponse(responseCode = "400", description = "Invalid redirect URI or scope")
    @ApiResponse(responseCode = "404", description = "No client with that client_id")
    public ClientResponse update(@PathVariable String clientId, @Valid @RequestBody UpdateClientRequest request) {
        return ClientResponse.from(clientAdminService.update(clientId, request.clientName(), request.redirectUris(),
                request.postLogoutRedirectUris(), request.scopes(), request.requireConsent()));
    }

    @DeleteMapping("/{clientId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(summary = "Delete a client", description = """
            Removes the client with its authorizations and consents: its refresh
            tokens stop working at once. Access tokens already issued are JWTs and
            stay valid until they expire.""")
    @ApiResponse(responseCode = "404", description = "No client with that client_id")
    public void delete(@PathVariable String clientId) {
        clientAdminService.delete(clientId);
    }

}
