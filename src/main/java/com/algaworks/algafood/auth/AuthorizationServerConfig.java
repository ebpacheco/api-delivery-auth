package com.algaworks.algafood.auth;

import java.time.Duration;
import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class AuthorizationServerConfig {

	@Bean
	public RegisteredClientRepository registeredClientRepository(PasswordEncoder passwordEncoder) {

		RegisteredClient algafoodWeb = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("algafood-web")
				.clientSecret(passwordEncoder.encode("web123"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("read").scope("write")
				.tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofHours(6)).build()).build();

		RegisteredClient checkToken = RegisteredClient.withId(UUID.randomUUID().toString()).clientId("check-token")
				.clientSecret(passwordEncoder.encode("check123"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).build();

		RegisteredClient foodAnalytics = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("algafood-analytic").clientSecret(passwordEncoder.encode("analytic123"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.redirectUri("http://localhost:8080/login/oauth2/code/algafood-analytic").scope("read").scope("write")
				.clientSettings(ClientSettings.builder().requireProofKey(false).build()) // desativa PKCE
				.build();

		return new InMemoryRegisteredClientRepository(algafoodWeb, checkToken, foodAnalytics);
	}

	@Bean
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();

		http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
				.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()))
				.apply(authorizationServerConfigurer);

		http.formLogin(Customizer.withDefaults());

		return http.build();
	}

	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.formLogin(Customizer.withDefaults()).csrf(csrf -> csrf.disable());

		return http.build();
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().issuer("http://localhost:8081").build();
	}
}
