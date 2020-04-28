package com.jdutton.photoapp.api.gateway.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	private final Environment env;

	public WebSecurity(Environment env) {
		super();
		this.env = env;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable(); // Disable Cross Site Request Forgery
		http.headers().frameOptions().disable();

		// We authorize request to pass through Zuul API Gateway:
		// Every request must be authenticated with the corresponding JWT,
		// unless it is
		// made to the User Registration Service, the User Login Service or the
		// H2 console.
		http.authorizeRequests()
				.antMatchers(env.getProperty("api.users.actuator.url.path"))
				.permitAll()
				.antMatchers(env.getProperty("api.zuul.actuator.url.path"))
				.permitAll()
				.antMatchers(env.getProperty("api.h2console.url.path"))
				.permitAll()
				.antMatchers(HttpMethod.POST,
						env.getProperty("api.registration.url.path"))
				.permitAll()
				.antMatchers(HttpMethod.POST,
						env.getProperty("api.login.url.path"))
				.permitAll().anyRequest().authenticated().and().addFilter(
						new AuthorizationFilter(authenticationManager(), env));

		http.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}

}
