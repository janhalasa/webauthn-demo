package com.github.janhalasa.webauthndemo;

import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Optional;

@Entity
@Getter
@NoArgsConstructor
public class Authenticator {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    @Column
    private String name;

    @Lob
    @Column(nullable = false)
    private ByteArray credentialId;

    @Lob
    @Column(nullable = false)
    private ByteArray publicKey;

    @ManyToOne
    private AppUser user;

    /* The authenticator potentially provides a range of additional information. This
     * application stores some of it to enable functionality that could be useful for
     * a production-quality web authentication project.
     */

    /**
     * The W3 recommendation strongly encourages authenticators to implement a signature count field that increments
     * each time the authenticator is used. By storing the 32-bit signCount integer provided by the authenticator,
     * the server can verify how many times the authenticator has been used. Increasing counts are expected;
     * if the authenticator reports a decreasing count, it should raise a red flag.
     */
    @Column(nullable = false)
    private Long count;

    /**
     * The aaguid field is an identifier that should be provided by authenticators (but isn’t always), which identifies
     * the type of credential used. This can be used to verify the authenticator’s make and model. Also,
     * it can be useful for denying access for outdated authenticators with known security vulnerabilities.
     */
    @Lob
    @Column(nullable = true)
    private ByteArray aaguid;

    public Authenticator(RegistrationResult result,
                         AuthenticatorAttestationResponse response,
                         AppUser user,
                         String name) {
        Optional<AttestedCredentialData> attestationData = response.getAttestation()
                .getAuthenticatorData()
                .getAttestedCredentialData();
        this.credentialId = result.getKeyId().getId();
        this.publicKey = result.getPublicKeyCose();
        this.aaguid = attestationData.get().getAaguid();
        this.count = result.getSignatureCount();
        this.name = name;
        this.user = user;
    }
}

