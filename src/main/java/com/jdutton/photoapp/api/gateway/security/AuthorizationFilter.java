package com.jdutton.photoapp.api.gateway.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class AuthorizationFilter extends BasicAuthenticationFilter {

	private final Environment env;

	public AuthorizationFilter(
			final AuthenticationManager authenticationManager,
			final Environment env) {
		super(authenticationManager);
		this.env = env;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// Try to retrieve Bearer JWT from Authorization header
		final String authorizationHeader = request
				.getHeader(env.getProperty("authorization.token.header.name"));

		// Found Bearer?
		// Not found
		if (StringUtils.isEmpty(authorizationHeader)
				|| !StringUtils.startsWith(authorizationHeader,
						env.getProperty("authorization.token.header.prefix"))) {
			chain.doFilter(request, response);
			return;
		}

		// Founded
		// Try to authenticate JWT
		final UsernamePasswordAuthenticationToken authentication = getAuthentication(
				request);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);

	}

	private UsernamePasswordAuthenticationToken getAuthentication(
			final HttpServletRequest request) {
		final String jwt = request
				.getHeader(env.getProperty("authorization.token.header.name"));
		// Header cannot be null here because it would have been filtered early
		// in the code
		// if(StringUtils.isEmpty(jwtHeaderName)) {
		// return null;
		// }

		// Remove header prefix
		final String token = StringUtils
				.removeStart(jwt,
						env.getProperty("authorization.token.header.prefix"))
				.trim();

		// We need to get the subject from the parsed JWT, which happens to be
		// the userId
		// final String userId = Jwts.parser()
		// .setSigningKey(Base64.getDecoder()
		// .decode(env.getProperty("token.secret")))
		// .parseClaimsJws(token).getBody().getSubject();

		final String userId = Jwts.parserBuilder()
				.setSigningKey(Base64.getDecoder()
						.decode(env.getProperty("token.secret")))
				.build().parseClaimsJws(token).getBody().getSubject();

		if (StringUtils.isEmpty(userId)) {
			return null;
		}

		return new UsernamePasswordAuthenticationToken(userId, null,
				new ArrayList<>());

	}
}
