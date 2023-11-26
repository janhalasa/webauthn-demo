package com.github.janhalasa.webauthndemo;

import com.github.janhalasa.webauthndemo.service.LocalCredentialRepository;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class WebauthnDemoApplication {

	public static void main(String[] args) {
		SpringApplication.run(WebauthnDemoApplication.class, args);
	}


	@Bean
	public RelyingParty relyingParty(
			LocalCredentialRepository localCredentialRepository,
			WebAuthnProperties properties) {

		RelyingPartyIdentity rpIdentity = RelyingPartyIdentity.builder()
				.id(properties.getHostName())
				.name(properties.getDisplay())
				.build();

		return RelyingParty.builder()
				.identity(rpIdentity)
				.credentialRepository(localCredentialRepository)
				.origins(properties.getOrigin())
				.build();
	}

}
