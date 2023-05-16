package com.Login.Security.service;

import java.util.Optional;

import com.Login.Security.exceções.LoginException;
import com.Login.Security.model.Usuario;
import com.Login.Security.repository.UsuarioRepository;

public class UsuarioService {

    private UsuarioRepository usuarioRepository;
    private Usuario usuario;

    public UsuarioService(UsuarioRepository usuarioRepository, Usuario usuario){
        this.usuarioRepository = usuarioRepository;
        this.usuario = usuario;

    }

    public Usuario autenticar(String email, String senha){
        Optional<Usuario> optionalUsuario = usuarioRepository.findBySenhaAndEmail(email, senha);
        if(optionalUsuario.isPresent()){
            usuario = optionalUsuario.get();
            if(!usuario.getSenha().equals(optionalUsuario) && !usuario.getEmail().equals(optionalUsuario)){
                throw new LoginException("Email ou senha incorretos");
            }
        } 
        return usuario;   
    }
}
