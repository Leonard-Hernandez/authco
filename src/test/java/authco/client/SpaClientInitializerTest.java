package authco.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.util.ReflectionTestUtils;

import authco.security.ClientScopes;

class SpaClientInitializerTest {

    private static final String CLIENT_ID = "finco-site";

    private ClientAdminService clientAdminService;
    private RegisteredClientRepository registeredClientRepository;
    private SpaClientInitializer initializer;

    @BeforeEach
    void setUp() {
        clientAdminService = mock(ClientAdminService.class);
        registeredClientRepository = mock(RegisteredClientRepository.class);
        initializer = new SpaClientInitializer(clientAdminService, registeredClientRepository);
        configure(CLIENT_ID);
    }

    private void configure(String clientId) {
        ReflectionTestUtils.setField(initializer, "clientId", clientId);
        ReflectionTestUtils.setField(initializer, "redirectUris", List.of("http://localhost:4200/auth/callback"));
        ReflectionTestUtils.setField(initializer, "postLogoutRedirectUris", List.of("http://localhost:4200/"));
    }

    @Test
    @DisplayName("first startup creates a public client without consent")
    void createsClientWhenMissing() {
        initializer.run(null);

        ArgumentCaptor<ClientDefinition> created = ArgumentCaptor.forClass(ClientDefinition.class);
        verify(clientAdminService).create(created.capture());
        ClientDefinition definition = created.getValue();
        assertEquals(CLIENT_ID, definition.clientId());
        assertEquals(ClientType.PUBLIC, definition.type());
        assertEquals(Set.of("http://localhost:4200/auth/callback"), definition.redirectUris());
        assertEquals(Set.of("http://localhost:4200/"), definition.postLogoutRedirectUris());
        assertEquals(ClientScopes.ALLOWED, definition.scopes());
        assertFalse(definition.requireConsent());
    }

    @Test
    @DisplayName("an existing client is left alone")
    void doesNothingWhenClientExists() {
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(mock(RegisteredClient.class));

        initializer.run(null);

        verify(clientAdminService, never()).create(any());
    }

    @Test
    @DisplayName("an empty client-id disables the seed")
    void doesNothingWhenDisabled() {
        configure("");

        initializer.run(null);

        verify(clientAdminService, never()).create(any());
    }

}
