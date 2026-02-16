package com.algaworks.algafood.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

@Configuration
public class JwtConfig {

	@Bean
	public RSAKey rsaKey() throws Exception {
		KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
		return new RSAKey.Builder((java.security.interfaces.RSAPublicKey) keyPair.getPublic())
				.privateKey(keyPair.getPrivate()).keyID("algaworks-key").build();
	}

	@Bean
	public JwtEncoder jwtEncoder(RSAKey rsaKey) {
		return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(rsaKey)));
	}

	@Bean
	public JwtDecoder jwtDecoder(RSAKey rsaKey) throws Exception {
		return NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build();
	}
}
