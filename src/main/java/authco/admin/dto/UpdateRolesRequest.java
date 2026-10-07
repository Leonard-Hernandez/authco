package authco.admin.dto;

import java.util.Set;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;

@Schema(description = "The complete set of roles the user must end up with; an empty set removes all")
public record UpdateRolesRequest(
        @NotNull @Schema(example = "[\"finco:premium\"]") Set<String> roles) {
}
