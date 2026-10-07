package authco.admin;

import java.util.List;
import java.util.Optional;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import authco.admin.dto.BanRequest;
import authco.admin.dto.UpdateRolesRequest;
import authco.admin.dto.UpdateUserRequest;
import authco.admin.dto.UserResponse;
import authco.user.UserAdminService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/admin/users")
@RequiredArgsConstructor
@Tag(name = "Users", description = "Edit, ban and assign roles to authco users")
public class AdminUserController {

    private final UserAdminService userAdminService;

    @GetMapping
    @Operation(summary = "List users", description = "Newest first. Filter by exact email to find one user.")
    public List<UserResponse> list(
            @Parameter(description = "Exact email to look up") @RequestParam Optional<String> email) {
        return userAdminService.list(email).stream().map(UserResponse::from).toList();
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get a user")
    @ApiResponse(responseCode = "404", description = "No user with that id")
    public UserResponse get(@PathVariable String id) {
        return UserResponse.from(userAdminService.get(id));
    }

    @PatchMapping("/{id}")
    @Operation(summary = "Edit a user", description = """
            Changes only the fields sent. The email cannot be edited: federated
            logins use it to link a new provider to an existing account.""")
    @ApiResponse(responseCode = "404", description = "No user with that id")
    public UserResponse update(@PathVariable String id, @Valid @RequestBody UpdateUserRequest request) {
        return UserResponse.from(userAdminService.update(id, request.name(), request.emailVerified()));
    }

    @PutMapping("/{id}/roles")
    @Operation(summary = "Replace a user's roles", description = """
            Sets the complete role set. Roles become scopes in the next access
            token the user receives, not in tokens already issued.""")
    @ApiResponse(responseCode = "400", description = "One or more roles do not exist")
    @ApiResponse(responseCode = "404", description = "No user with that id")
    public UserResponse replaceRoles(@PathVariable String id, @Valid @RequestBody UpdateRolesRequest request) {
        return UserResponse.from(userAdminService.replaceRoles(id, request.roles()));
    }

    @PostMapping("/{id}/ban")
    @Operation(summary = "Ban a user", description = """
            authco refuses to issue new tokens to the user, including refreshes.
            Access tokens already issued stay valid until they expire.""")
    @ApiResponse(responseCode = "404", description = "No user with that id")
    public UserResponse ban(@PathVariable String id, @Valid @RequestBody BanRequest request) {
        return UserResponse.from(userAdminService.ban(id, request.reason()));
    }

    @DeleteMapping("/{id}/ban")
    @Operation(summary = "Lift a ban")
    @ApiResponse(responseCode = "404", description = "No user with that id")
    public UserResponse unban(@PathVariable String id) {
        return UserResponse.from(userAdminService.unban(id));
    }

}
