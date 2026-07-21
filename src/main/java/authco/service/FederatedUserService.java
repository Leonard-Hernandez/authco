package authco.service;

import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Service;

import authco.user.FederatedIdentityEntity;
import authco.user.RoleEntity;
import authco.user.UserEntity;
import authco.user.repository.FederatedIdentityRepository;
import authco.user.repository.RoleRepository;
import authco.user.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class FederatedUserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final FederatedIdentityRepository federatedIdentityRepository;

    @Transactional
    public UserEntity findOrCreate(String provider, String providerUserId,
            String email, String name) {

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

        RoleEntity role = roleRepository.findByName("USER").get();

        newUser.setEmail(email);
        newUser.setEnabled(true);
        newUser.setName(name);
        newUser.setRoles(Set.of(role));


        UserEntity newSavedUser = userRepository.save(newUser);


        FederatedIdentityEntity federatedIdentityEntity = new FederatedIdentityEntity();
        federatedIdentityEntity.setProvider(provider);
        federatedIdentityEntity.setProviderUserId(providerUserId);
        federatedIdentityEntity.setUser(newSavedUser);

        federatedIdentityRepository.save(federatedIdentityEntity);

        return newSavedUser;
    }

}
