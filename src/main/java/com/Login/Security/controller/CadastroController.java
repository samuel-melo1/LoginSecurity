package com.Login.Security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;
import com.Login.Security.model.Usuario;
import com.Login.Security.service.UsuarioService;
import jakarta.servlet.http.HttpServletRequest;

@Controller
public class CadastroController {

    private UsuarioService usuarioService;

    public CadastroController(UsuarioService usuarioService){
        this.usuarioService = usuarioService;
    }

    @GetMapping("/cadastrar")
    public ModelAndView cadastrar(){
     ModelAndView mv = new ModelAndView("cadastrar");
     return mv;
    }

    @PostMapping("/cadastrar")
    public ModelAndView cadastrarUser(@ModelAttribute("usuario") Usuario usuario, HttpServletRequest request){
      usuario.setEmail(request.getParameter("email"));
      usuario.setSenha(request.getParameter("senha"));
      System.out.println(usuario.getEmail());
      System.out.println(usuario.getSenha());
      System.out.println();
      usuarioService.salvarUsuario(usuario);
      ModelAndView mv = new ModelAndView("redirect:/login");
      mv.addObject("usuario", new Usuario());
      return mv;
  
    }
 
}
