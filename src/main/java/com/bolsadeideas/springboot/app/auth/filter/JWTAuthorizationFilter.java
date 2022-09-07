package com.bolsadeideas.springboot.app.auth.filter;
import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;
import com.bolsadeideas.springboot.app.auth.service.JWTService;
import com.bolsadeideas.springboot.app.auth.service.JWTServiceImpl;


/**
 * 
 * 
 * REcordar agregar al filtro en spring security
 *
 */

public class JWTAuthorizationFilter extends BasicAuthenticationFilter {
	
	private JWTService jwtService;

	public JWTAuthorizationFilter(AuthenticationManager authenticationManager, JWTService jwtService) {
		super(authenticationManager);
		
		this.jwtService = jwtService;
	}

	
	//Este metodo viene de aqui BasicAuthenticationFilter
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		String header = request.getHeader(HttpHeaders.AUTHORIZATION);
		
		if (!requireAuthentication(header)) {
			
			chain.doFilter(request, response);
			return;
		}
		
		
		
		
		UsernamePasswordAuthenticationToken authentication = null;
		
		//VErificar si el token es correcto obtener el usario y los roles
		if(jwtService.validateToken(header)) {
			
			
			authentication = new UsernamePasswordAuthenticationToken(jwtService.getUsername(header), null, jwtService.getRoles(header));
			
		}
		
		SecurityContextHolder.getContext().setAuthentication(authentication);//Se encarga de manejar el contexto de seguridad
		chain.doFilter(request, response);//continuamos con la caden a de ejecucion del request para los filtros y controladores de spring
		
	}
	
	protected boolean requireAuthentication(String header) {
		
		if (!StringUtils.startsWithIgnoreCase(header, JWTServiceImpl.TOKEN_PREFIX)) {
			
			
			return false;
		}

	return true;
	}
	
	
	

}
