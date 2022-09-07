package com.bolsadeideas.springboot.app.auth.service;

import java.io.IOException;
import java.util.Collection;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import com.fasterxml.jackson.core.JsonProcessingException;

import io.jsonwebtoken.Claims;

public interface JWTService {
	
	public String createToken(Authentication authentication) throws IOException;
	public boolean validateToken(String token);
	public Claims getClaims(String token);
	public String getUsername(String token);//Obtener el username desde el token
	public Collection<? extends GrantedAuthority> getRoles(String token) throws IOException;
	public String resolveToken(String token);
}
