package com.example.redisAuth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

@Component
public class RedisAuthenticationProvider implements AuthenticationProvider {

	private static final Logger logger = LoggerFactory.getLogger(RedisAuthenticationProvider.class);

	@Autowired
	private StringRedisTemplate redisTemplate;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		Object username = authentication.getPrincipal();
		Object password = authentication.getCredentials();
		logger.info("ユーザー名 = {}、パスワード = {}", username, password);

		if(redisTemplate.hasKey(username.toString())) {
			logger.info("has key");
			return new UsernamePasswordAuthenticationToken(username, password,
					AuthorityUtils.createAuthorityList("ROLE_USER"));
		} else {
			logger.info("don't has key");
			throw new BadCredentialsException("user state is illegal.");
		}
	}

	@Override
	public boolean supports(Class<?> aClass) {
		return aClass.isAssignableFrom(UsernamePasswordAuthenticationToken.class);
	}
}