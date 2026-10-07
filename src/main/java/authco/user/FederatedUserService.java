package authco.user;

import java.util.Optional;

import org.springframework.stereotype.Service;

import authco.user.exception.UnverifiedEmailException;
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
    public UserEntity findOrCreate(FederatedProfile federateProfile) {

        if (!federateProfile.emailVerified()) {
            throw new UnverifiedEmailException();
        }

        Optional<FederatedIdentityEntity> federateOptional = federatedIdentityRepository
                .findByProviderAndProviderUserId(federateProfile.provider(), federateProfile.providerUserId());

        if (federateOptional.isPresent()) {
            return federateOptional.get().getUser();
        }

        Optional<UserEntity> userOptional = userRepository.findByEmail(federateProfile.email());

        if (userOptional.isPresent()) {

            FederatedIdentityEntity federatedIdentityEntity = new FederatedIdentityEntity();
            federatedIdentityEntity.setProvider(federateProfile.provider());
            federatedIdentityEntity.setProviderUserId(federateProfile.providerUserId());
            federatedIdentityEntity.setUser(userOptional.get());

            federatedIdentityRepository.save(federatedIdentityEntity);

            return userOptional.get();

        }

        UserEntity newUser = new UserEntity();

        newUser.setEmail(federateProfile.email());
        newUser.setName(federateProfile.name());
        newUser.setEmailVerified(federateProfile.emailVerified());

        UserEntity newSavedUser = userRepository.save(newUser);

        FederatedIdentityEntity federatedIdentityEntity = new FederatedIdentityEntity();
        federatedIdentityEntity.setProvider(federateProfile.provider());
        federatedIdentityEntity.setProviderUserId(federateProfile.providerUserId());
        federatedIdentityEntity.setUser(newSavedUser);

        federatedIdentityRepository.save(federatedIdentityEntity);

        return newSavedUser;
    }

}
