package authco.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalAnswers.returnsFirstArg;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import authco.user.exception.UnknownRoleException;
import authco.user.exception.UserNotFoundException;
import authco.user.repository.RoleRepository;
import authco.user.repository.UserRepository;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class UserAdminServiceTest {

    private static final String USER_ID = "0e4d7594-2f25-4080-8d98-5abf1cce43e1";

    @Mock
    private UserRepository userRepository;

    @Mock
    private RoleRepository roleRepository;

    @InjectMocks
    private UserAdminService userAdminService;

    private UserEntity user;

    @BeforeEach
    void setUp() {
        user = new UserEntity();
        user.setId(USER_ID);
        user.setEmail("user@example.com");
        user.setName("Original Name");
        when(userRepository.findById(USER_ID)).thenReturn(Optional.of(user));
        when(userRepository.save(any(UserEntity.class))).then(returnsFirstArg());
    }

    private static RoleEntity role(String name) {
        RoleEntity role = new RoleEntity();
        role.setName(name);
        return role;
    }

    @Test
    @DisplayName("an unknown user id raises UserNotFoundException")
    void getUnknownUserFails() {
        when(userRepository.findById("missing")).thenReturn(Optional.empty());

        assertThrows(UserNotFoundException.class, () -> userAdminService.get("missing"));
    }

    @Test
    @DisplayName("filtering by email returns only that user, or nothing")
    void listByEmail() {
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.of(user));
        when(userRepository.findByEmail("nobody@example.com")).thenReturn(Optional.empty());

        assertEquals(List.of(user), userAdminService.list(Optional.of("user@example.com")));
        assertTrue(userAdminService.list(Optional.of("nobody@example.com")).isEmpty());
        verify(userRepository, never()).findAllByOrderByCreatedAtDesc();
    }

    @Test
    @DisplayName("update changes only the fields that are sent")
    void updateIgnoresNullFields() {
        UserEntity updated = userAdminService.update(USER_ID, null, true);

        assertEquals("Original Name", updated.getName());
        assertTrue(updated.isEmailVerified());
    }

    @Test
    @DisplayName("replacing roles with an unknown name fails and changes nothing")
    void replaceRolesRejectsUnknownRoles() {
        user.getRoles().add(role("finco:premium"));
        when(roleRepository.findByNameIn(Set.of("finco:premium", "finco:god")))
                .thenReturn(List.of(role("finco:premium")));

        UnknownRoleException e = assertThrows(UnknownRoleException.class,
                () -> userAdminService.replaceRoles(USER_ID, Set.of("finco:premium", "finco:god")));

        assertTrue(e.getMessage().contains("finco:god"));
        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("replacing roles sets exactly the requested set")
    void replaceRolesReplacesTheWholeSet() {
        user.getRoles().add(role("finco:admin"));
        when(roleRepository.findByNameIn(Set.of("finco:premium"))).thenReturn(List.of(role("finco:premium")));

        UserEntity updated = userAdminService.replaceRoles(USER_ID, Set.of("finco:premium"));

        Set<String> names = updated.getRoles().stream().map(RoleEntity::getName).collect(Collectors.toSet());
        assertEquals(Set.of("finco:premium"), names);
    }

    @Test
    @DisplayName("ban records when and why; unban clears both")
    void banAndUnban() {
        UserEntity banned = userAdminService.ban(USER_ID, "abuse");

        assertTrue(banned.isBanned());
        assertNotNull(banned.getBannedAt());
        assertEquals("abuse", banned.getBanReason());

        UserEntity unbanned = userAdminService.unban(USER_ID);

        assertFalse(unbanned.isBanned());
        assertNull(unbanned.getBanReason());
    }

}
