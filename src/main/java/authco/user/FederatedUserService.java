package authco.user;

import java.util.Optional;

import org.springframework.stereotype.Service;

import authco.user.repository.FederatedIdentityRepository;
import authco.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class FederatedUserService {

    private final UserRepository userRepository;
    private final FederatedIdentityRepository federatedIdentityRepository;

    @Transactional
    public UserEntity findOrCreate(String provider, String providerUserId,
            String email, String name, boolean isEmailVerified) {

        Optional<FederatedIdentityEntity> federateOptional = federatedIdentityRepository
                .findByProviderAndProviderUserId(provider, providerUserId);

        if (federateOptional.isPresent()) {
            return userRepository.findByEmail(email).get();
        }

        Optional<UserEntity> userOptional = userRepository.findByEmail(email);

        if (userOptional.isPresent()) {
            FederatedIdentityEntity federatedIdentityEntity = new FederatedIdentityEntity();
            federatedIdentityEntity.setProvider(provider);
            federatedIdentityEntity.setProviderUserId(providerUserId);
            federatedIdentityEntity.setUser(userOptional.get());

            federatedIdentityRepository.save(federatedIdentityEntity);

            return userOptional.get();
        }

        UserEntity newUser = new UserEntity();

        newUser.setEmail(email);
        newUser.setName(name);
        newUser.setEmailVerified(isEmailVerified);

        UserEntity newSavedUser = userRepository.save(newUser);

        FederatedIdentityEntity federatedIdentityEntity = new FederatedIdentityEntity();
        federatedIdentityEntity.setProvider(provider);
        federatedIdentityEntity.setProviderUserId(providerUserId);
        federatedIdentityEntity.setUser(newSavedUser);

        federatedIdentityRepository.save(federatedIdentityEntity);

        return newSavedUser;
    }

}
