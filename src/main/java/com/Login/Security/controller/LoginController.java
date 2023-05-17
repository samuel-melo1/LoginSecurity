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
public class LoginController {

    private UsuarioService usuarioService;
    
    public LoginController(UsuarioService usuarioService){
        this.usuarioService = usuarioService;
    }

  @GetMapping("/login")
  public ModelAndView login() {
    ModelAndView mv = new ModelAndView("login");
    mv.addObject("usuario", new Usuario());
    return mv;
  }

  @PostMapping("/login")
public ModelAndView logar(@ModelAttribute("usuario") Usuario usuario,
        HttpServletRequest request) {
    usuario.setEmail(request.getParameter("email"));
    usuario.setSenha(request.getParameter("senha"));
    Usuario usuarioSalvo = usuarioService.autenticar(usuario.getEmail(), usuario.getSenha());
    ModelAndView mv = new ModelAndView("redirect:/home");
    mv.addObject("usuarioSalvo", usuarioSalvo);
    return mv;
}
}