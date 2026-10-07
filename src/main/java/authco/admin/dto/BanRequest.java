package authco.admin.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record BanRequest(
        @NotBlank @Size(max = 255) @Schema(example = "Abuse of the API") String reason) {
}
