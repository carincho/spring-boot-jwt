package com.bolsadeideas.springboot.app.auth.filter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.bolsadeideas.springboot.app.auth.service.JWTService;
import com.bolsadeideas.springboot.app.auth.service.JWTServiceImpl;
import com.bolsadeideas.springboot.app.models.entity.Usuario;
import com.fasterxml.jackson.databind.ObjectMapper;



/**
 * 
 * 
 * Heredar de UsernamePasswordAuthenticationFilter
 * Se ejecuta cada bez que queremos iniciar session Cuando la ruta es api/login del tipo post
 *
 */
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	
	
	private AuthenticationManager authenticationManager;
	private JWTService jwtService;
	

	//Se encarga de realizar segun nuestro proveedor service
	public JWTAuthenticationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		this.authenticationManager = authenticationManager;
		setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login","POST"));
		this.jwtService = jwtService;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		
		
		String username = obtainUsername(request);
////		String username = request.getParameter("username");//Es lo mismo que arriba
//		username = (username != null) ? username.trim() : "";
//		
		String password = obtainPassword(request);
////		String password = request.getParameter("password"); //Lo mismo que arriba
//		password = (password != null) ? password : "";

		
		if(username != null && password != null) {
			
			logger.info("username desde request parameter (form-data): " + username);
			logger.info("password desde request parameter (form-data): " + password);
			
		} else {
			
			Usuario user = null;
			
			try {
				
				 user = new ObjectMapper().readValue(request.getInputStream(), Usuario.class);//Convertgir los datos que estamos recibiendo en input stream esto es para recibir en RAW
				 
				 username = user.getUsername();
				 password = user.getPassword();
				 
				 logger.info("username desde request InputStream (RAW): " + username);
				logger.info("password desde request InputStream (RAW): " + password);
				 
				
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
		
		//Se encarga de contener las credenciales 
	
		UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password);
		
		//Se retorna la autenticacion la autenticacion se realiza con el UsernamePAsswordAuthenticationToken
		
		return authenticationManager.authenticate(authToken);
	}

	
	//Aqui esta Authentication igual que UsernamePasswordAuthenticationToken pero aqui ya esta autenticado
	//Estos metodos son de la clase AbstractAuthenticationProcessingFilter unsuccessfulAuthentication y successfulAuthentication
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		

	
		String token = jwtService.createToken(authResult);
		
		response.addHeader(JWTServiceImpl.HEADER_STRING, JWTServiceImpl.TOKEN_PREFIX .concat(token));//Siempre usar Bearer en el token y la cabecera Authorization
		
		Map<String, Object>body = new HashMap<String, Object>(); //para enviarlo en formato json
		body.put("token", token);
		body.put("user", (User)authResult.getPrincipal());
		body.put("mensaje", String.format("Hola %s, has iniciado sesion con exito", authResult.getName()));
		
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(200);
		response.setContentType("application/json");
	
		
//		super.successfulAuthentication(request, response, chain, authResult);//Se quita por que tenemos nuestra propia implementacion
	}

	
	// si el login falla
	@Override
	protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException failed) throws IOException, ServletException {
		
		Map<String, Object>body = new HashMap<String, Object>();
		body.put("mensaje", "Error de autenticacion: username o password incorrecto");//por seguridad se indica que uno de los dos 
		body.put("Error", failed.getMessage());
		
		response.getWriter().write(new ObjectMapper().writeValueAsString(body));
		response.setStatus(401);// no autorizado 401 o 403
		response.setContentType("application/json");
		
		
	}
	
	
	

}
