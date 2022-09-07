package com.bolsadeideas.springboot.app.auth.service;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;
import org.springframework.util.Base64Utils;

import com.bolsadeideas.springboot.app.auth.SimpleGrantedAuthorityMixin;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Service
public class JWTServiceImpl implements JWTService {

	
	public static final String SECRET = Base64Utils.encodeToString("Mi.Llave.Secreta.carincho.123456".getBytes());
	public static final long EXPIRATION_DATE =  3600000 * 4L;
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING = "Authorization";
	
	private final static SecretKey secretKey = new SecretKeySpec(SECRET.getBytes(), SignatureAlgorithm.HS256.getJcaName());
	
	

	@Override
	public String createToken(Authentication authentication) throws IOException {

		String username = ((User) authentication.getPrincipal()).getUsername();

		Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();
		Claims claims = Jwts.claims();
		claims.put("authorities", new ObjectMapper().writeValueAsString(roles));

		//
		String token = Jwts.builder().setClaims(claims).setSubject(username)// se puede obtener asi authResult.getName()
				.signWith(secretKey).setIssuedAt(new Date())
				.setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_DATE)).compact();// compactar y crear token

		return token;
	}

	@Override
	public boolean validateToken(String token) {

		// implementar la validacion del token

		try {

			getClaims(token);

			return true;

		} catch (JwtException | IllegalArgumentException e) {

			return false;
		}

	}

	@Override
	public Claims getClaims(String token) {

		Claims claims = Jwts.parserBuilder().setSigningKey(SECRET.getBytes()).build()
				.parseClaimsJws(resolveToken(token)).getBody();// Esto es solo para obtener los datos todas las
																		// demas lineas se valida

		return claims;
	}

	@Override
	public String getUsername(String token) {

		return getClaims(token).getSubject();
	}

	@Override
	public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException {

		Object roles = getClaims(token).get("authorities");

		// Asignar el objeto authentication dentro del contexto autentica al usuario
		// dentro de la peticion
		Collection<? extends GrantedAuthority> authorities = Arrays
				.asList(new ObjectMapper().addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)//Aqui se agrega el mixin la clase primero la clase objetivo y el complemento SimpleGrantedAuthority no tiene constructor defautl que se le agrega el rol
						.readValue(roles.toString().getBytes(), SimpleGrantedAuthority[].class));
		
		return authorities;
	}

	@Override
	public String resolveToken(String token) {
		if (token != null && token.startsWith(TOKEN_PREFIX)) {
			return token.replace(TOKEN_PREFIX, "");

		}

		return null;
	}

}
