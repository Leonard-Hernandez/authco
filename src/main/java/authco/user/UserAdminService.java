package authco.user;

import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import authco.user.exception.UnknownRoleException;
import authco.user.exception.UserNotFoundException;
import authco.user.repository.RoleRepository;
import authco.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserAdminService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public List<UserEntity> list(Optional<String> email) {
        return email
                .map(e -> userRepository.findByEmail(e).map(List::of).orElse(List.of()))
                .orElseGet(userRepository::findAllByOrderByCreatedAtDesc);
    }

    public UserEntity get(String userId) {
        return userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(userId));
    }

    // Email is deliberately not editable: it is the key federated logins use to
    // link a new provider to an existing account.
    @Transactional
    public UserEntity update(String userId, String name, Boolean emailVerified) {
        UserEntity user = get(userId);
        if (name != null) {
            user.setName(name);
        }
        if (emailVerified != null) {
            user.setEmailVerified(emailVerified);
        }
        return userRepository.save(user);
    }

    // Replaces the whole set, so the request body is the final state of the user's roles.
    @Transactional
    public UserEntity replaceRoles(String userId, Set<String> roleNames) {
        UserEntity user = get(userId);

        List<RoleEntity> roles = roleRepository.findByNameIn(roleNames);
        Set<String> found = roles.stream().map(RoleEntity::getName).collect(Collectors.toSet());
        Set<String> unknown = new HashSet<>(roleNames);
        unknown.removeAll(found);
        if (!unknown.isEmpty()) {
            throw new UnknownRoleException(unknown);
        }

        user.setRoles(new HashSet<>(roles));
        return userRepository.save(user);
    }

    // Takes effect on the next token request (SubjectTokenCustomizer refuses banned
    // users). Access tokens already issued stay valid until they expire.
    @Transactional
    public UserEntity ban(String userId, String reason) {
        UserEntity user = get(userId);
        user.setBannedAt(Instant.now());
        user.setBanReason(reason);
        return userRepository.save(user);
    }

    @Transactional
    public UserEntity unban(String userId) {
        UserEntity user = get(userId);
        user.setBannedAt(null);
        user.setBanReason(null);
        return userRepository.save(user);
    }

}
