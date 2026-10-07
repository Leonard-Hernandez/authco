package authco.user;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import authco.config.TestContainerConfig;
import authco.user.exception.UnverifiedEmailException;
import authco.user.repository.FederatedIdentityRepository;
import authco.user.repository.UserRepository;

/**
 * The multi-provider identity rules against the real schema: one authco user,
 * many federated identities, linked by verified email only.
 */
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestContainerConfig.class)
@ActiveProfiles("test")
class FederatedUserServiceIntegrationTest {

    @Autowired
    private FederatedUserService federatedUserService;

    @Autowired
    private FederatedIdentityRepository federatedIdentityRepository;

    @Autowired
    private UserRepository userRepository;

    private static String uniqueEmail() {
        return "fed-" + UUID.randomUUID() + "@example.com";
    }

    private static String uniqueSub() {
        return UUID.randomUUID().toString();
    }

    @Test
    @DisplayName("a first login creates the user and links the provider identity")
    void firstLoginCreatesUser() {
        String email = uniqueEmail();
        String googleSub = uniqueSub();

        UserEntity user = federatedUserService.findOrCreate(
                new FederatedProfile("google", googleSub, email, true, "Ada"));

        assertEquals(email, userRepository.findById(user.getId()).orElseThrow().getEmail());
        assertTrue(federatedIdentityRepository.findByProviderAndProviderUserId("google", googleSub).isPresent());
    }

    @Test
    @DisplayName("logging in again with the same provider returns the same user")
    void sameProviderSameUser() {
        FederatedProfile profile = new FederatedProfile("google", uniqueSub(), uniqueEmail(), true, "Ada");

        UserEntity first = federatedUserService.findOrCreate(profile);
        UserEntity second = federatedUserService.findOrCreate(profile);

        assertEquals(first.getId(), second.getId());
    }

    @Test
    @DisplayName("a second provider with the same verified email links to the same user")
    void secondProviderLinksToSameUser() {
        String email = uniqueEmail();

        UserEntity viaGoogle = federatedUserService.findOrCreate(
                new FederatedProfile("google", uniqueSub(), email, true, "Ada"));
        UserEntity viaGithub = federatedUserService.findOrCreate(
                new FederatedProfile("github", uniqueSub(), email, true, "Ada"));

        // The whole point of the authco id: same person, same subject, whatever the provider.
        assertEquals(viaGoogle.getId(), viaGithub.getId());
    }

    @Test
    @DisplayName("a second provider with an unverified email is refused and links nothing")
    void unverifiedEmailCannotLink() {
        String email = uniqueEmail();
        String githubSub = uniqueSub();
        federatedUserService.findOrCreate(new FederatedProfile("google", uniqueSub(), email, true, "Ada"));

        assertThrows(UnverifiedEmailException.class, () -> federatedUserService.findOrCreate(
                new FederatedProfile("github", githubSub, email, false, "Mallory")));

        assertTrue(federatedIdentityRepository.findByProviderAndProviderUserId("github", githubSub).isEmpty());
    }

    @Test
    @DisplayName("an unverified email never creates an account (blocks pre-account takeover)")
    void unverifiedEmailCannotCreateAccount() {
        // The attack: someone signs up first through a provider that doesn't verify
        // emails, using the victim's address. If that created an account, the victim's
        // later verified login would either link into it or be locked out of the email.
        String victimEmail = uniqueEmail();
        String attackerSub = uniqueSub();

        assertThrows(UnverifiedEmailException.class, () -> federatedUserService.findOrCreate(
                new FederatedProfile("github", attackerSub, victimEmail, false, "Mallory")));

        assertTrue(userRepository.findByEmail(victimEmail).isEmpty());
        assertTrue(federatedIdentityRepository.findByProviderAndProviderUserId("github", attackerSub).isEmpty());

        // The real owner, verified, still gets a clean account of their own.
        UserEntity owner = federatedUserService.findOrCreate(
                new FederatedProfile("google", uniqueSub(), victimEmail, true, "Ada"));
        assertEquals(victimEmail, owner.getEmail());
    }

}
