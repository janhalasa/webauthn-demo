package com.github.janhalasa.webauthndemo.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.github.janhalasa.webauthndemo.AppUser;
import com.github.janhalasa.webauthndemo.Authenticator;
import com.github.janhalasa.webauthndemo.repository.AuthenticatorRepository;
import com.github.janhalasa.webauthndemo.repository.UserRepository;
import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.ui.Model;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.util.Random;

@Service
public class WebAuthnService {

    private static final Logger LOG = LoggerFactory.getLogger(WebAuthnService.class);

    private final UserRepository userRepo;
    private final AuthenticatorRepository authRepository;
    private final RelyingParty relyingParty;

    public WebAuthnService(
            UserRepository userRepo,
            AuthenticatorRepository authRepository,
            RelyingParty relyingParty) {
        this.userRepo = userRepo;
        this.authRepository = authRepository;
        this.relyingParty = relyingParty;
    }

    public String registerUser(
            String username,
            String displayName,
            HttpSession session) {
        AppUser existingUser = this.userRepo.findByUsername(username);
        if (existingUser != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Username " + username
                    + " already exists. Choose a new name.");
        }
        byte[] bytes = new byte[32];
        new Random().nextBytes(bytes);
        ByteArray id = new ByteArray(bytes);

        UserIdentity userIdentity = UserIdentity.builder()
                .name(username)
                .displayName(displayName)
                .id(id)
                .build();
        AppUser user = new AppUser(userIdentity);
        this.userRepo.save(user);
        return createDataForPasskeyRegistration(user, session);
    }

    public String createDataForPasskeyRegistration(
            AppUser user,
            HttpSession session) {
        AppUser existingUser = this.userRepo.findByHandle(user.getHandle());
        if (existingUser == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User " + user.getUsername()
                    + " does not exist. Please register.");
        }

        UserIdentity userIdentity = user.toUserIdentity();
        StartRegistrationOptions registrationOptions = StartRegistrationOptions.builder()
                .user(userIdentity)
                .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                        .userVerification(UserVerificationRequirement.REQUIRED)
                        .build())
                .build();
        PublicKeyCredentialCreationOptions registration = relyingParty.startRegistration(registrationOptions);
        session.setAttribute(userIdentity.getName(), registration);
        try {
            return registration.toCredentialsCreateJson();
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error processing JSON.", e);
        }
    }

    public ModelAndView saveRegistration(
            String credential,
            String username,
            String credentialName,
            HttpSession session) {
        try {
            AppUser user = this.userRepo.findByUsername(username);
            PublicKeyCredentialCreationOptions requestOptions =
                    (PublicKeyCredentialCreationOptions) session.getAttribute(user.getUsername());
            if (requestOptions == null) {
                throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                        "Cached request expired. Try to register again!");
            }
            PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs> publicKeyCredential =
                    PublicKeyCredential.parseRegistrationResponseJson(credential);

            LOG.info("Origin: {}, Type: {}",
                    publicKeyCredential.getResponse().getClientData().getOrigin(),
                    publicKeyCredential.getResponse().getClientData().getType());

            FinishRegistrationOptions finishRegistrationOptions = FinishRegistrationOptions.builder()
                    .request(requestOptions)
                    .response(publicKeyCredential)
                    .build();
            RegistrationResult result = relyingParty.finishRegistration(finishRegistrationOptions);
            Authenticator savedAuth = new Authenticator(result, publicKeyCredential.getResponse(), user, credentialName);
            authRepository.save(savedAuth);
            return new ModelAndView("redirect:/login", HttpStatus.SEE_OTHER);
        } catch (RegistrationFailedException e) {
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Registration failed.", e);
        } catch (IOException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Failed to save credenital, please try again!", e);
        }
    }

    public String finishAuthentication(
            String credential,
            String username,
            Model model,
            HttpSession session) {
        if (credential == null || credential.trim().isEmpty()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Parameter credential is required");
        }
        try {
            PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs> pkc
                    = PublicKeyCredential.parseAssertionResponseJson(credential);
            AssertionRequest request = (AssertionRequest) session.getAttribute(username);
            AssertionResult result = relyingParty.finishAssertion(FinishAssertionOptions.builder()
                    .request(request)
                    .response(pkc)
                    .build());

            LOG.info("AssertionRequest: {}", request.toJson());
            LOG.info("AssertionResult: {}", result.toString());

            if (result.isSuccess()) {
                model.addAttribute("username", username);
                return "welcome";
            }
            return "index";
        } catch (IOException | AssertionFailedException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authentication failed", e);
        }
    }

    public String initAuthentication(String username, HttpSession session) {
        AssertionRequest request = relyingParty.startAssertion(StartAssertionOptions.builder()
                .userVerification(UserVerificationRequirement.REQUIRED)
                .username(username)
                .build());
        try {
            if (username != null) {
                session.setAttribute(username, request);
            }
            return request.toCredentialsGetJson();
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }
    }
}
