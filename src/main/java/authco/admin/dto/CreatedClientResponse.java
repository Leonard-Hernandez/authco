package authco.admin.dto;

import authco.client.CreatedClient;
import io.swagger.v3.oas.annotations.media.Schema;

public record CreatedClientResponse(
        ClientResponse client,
        @Schema(description = "Only for CONFIDENTIAL clients, and only in this response. Store it now: "
                + "authco keeps just its hash.") String clientSecret) {

    public static CreatedClientResponse from(CreatedClient created) {
        return new CreatedClientResponse(ClientResponse.from(created.client()), created.clientSecret());
    }
}
