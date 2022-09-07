package com.bolsadeideas.springboot.app.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class SimpleGrantedAuthorityMixin {

	
	//La marca para indicar que el constructor por defecto cuando se creen objetos authorities a paritr del json
	//JsonProperty("authority") String role para inyectar el valor del json al atributo role que el nombre proviene del 
	//Json en el token de roles en el la seccion payload
	//
	@JsonCreator
	public SimpleGrantedAuthorityMixin(@JsonProperty("authority") String role) {
	}
	
	

}
