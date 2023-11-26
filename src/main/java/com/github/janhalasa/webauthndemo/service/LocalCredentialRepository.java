package com.github.janhalasa.webauthndemo.service;

import com.github.janhalasa.webauthndemo.AppUser;
import com.github.janhalasa.webauthndemo.Authenticator;
import com.github.janhalasa.webauthndemo.repository.AuthenticatorRepository;
import com.github.janhalasa.webauthndemo.repository.UserRepository;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class LocalCredentialRepository implements CredentialRepository {

    private final UserRepository userRepo;
    private final AuthenticatorRepository authRepository;

    public LocalCredentialRepository(
            UserRepository userRepo,
            AuthenticatorRepository authRepository) {
        this.userRepo = userRepo;
        this.authRepository = authRepository;
    }

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        final AppUser user = userRepo.findByUsername(username);
        final List<Authenticator> auth = authRepository.findAllByUser(user);
        return auth.stream()
                .map(credential ->
                        PublicKeyCredentialDescriptor.builder()
                                .id(credential.getCredentialId())
                                .build())
                .collect(Collectors.toSet());
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        final AppUser user = userRepo.findByUsername(username);
        return Optional.of(user.getHandle());
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        AppUser user = userRepo.findByHandle(userHandle);
        return Optional.of(user.getUsername());
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        final Optional<Authenticator> auth = authRepository.findByCredentialId(credentialId);
        return auth.map(credential ->
                RegisteredCredential.builder()
                        .credentialId(credential.getCredentialId())
                        .userHandle(credential.getUser().getHandle())
                        .publicKeyCose(credential.getPublicKey())
                        .signatureCount(credential.getCount())
                        .build()
        );
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        final List<Authenticator> auth = authRepository.findAllByCredentialId(credentialId);
        return auth.stream()
                .map(credential ->
                        RegisteredCredential.builder()
                                .credentialId(credential.getCredentialId())
                                .userHandle(credential.getUser().getHandle())
                                .publicKeyCose(credential.getPublicKey())
                                .signatureCount(credential.getCount())
                                .build())
                .collect(Collectors.toSet());
    }
}
