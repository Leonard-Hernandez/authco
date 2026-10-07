package authco.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Size;

@Schema(description = "Fields to change; omitted or null fields are left as they are. Email is not editable.")
public record UpdateUserRequest(
        @Size(max = 255) String name,
        Boolean emailVerified) {
}
