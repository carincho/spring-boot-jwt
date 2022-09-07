package com.bolsadeideas.springboot.app.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.bolsadeideas.springboot.app.models.service.IClienteService;
import com.bolsadeideas.springboot.app.view.xml.ClienteList;


/**
 * 
 * 
 * Con RestController ya no necesitamos ResponseBody
 *
 */
@RestController
@RequestMapping("/api/clientes")
@Secured("ROLE_ADMIN")
public class ClienteRestController {
	
	@Autowired
	private IClienteService clienteService;
	
	/**
	 * 
	 * 
	 * Servicio REST
	 * 
	 * @ResponseBody significa listado de clientes se va a almacenar en el cuerpo de la respuesta spring va a asimilar que es un REST
	 */
	@GetMapping(value = "/listar")
	public ClienteList listar() {
		
		
		
		return new ClienteList( clienteService.findAll());
		
	}

}
