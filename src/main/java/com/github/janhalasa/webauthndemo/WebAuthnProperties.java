package com.github.janhalasa.webauthndemo;

import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import lombok.Getter;
import lombok.Setter;

@Configuration
@Getter
@Setter
@ConfigurationProperties(prefix = "webauthn")
public class WebAuthnProperties {
    private String hostName;
    private String display;
    private Set<String> origin;
}
