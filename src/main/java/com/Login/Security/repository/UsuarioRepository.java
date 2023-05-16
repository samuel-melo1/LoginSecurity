package com.Login.Security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.Login.Security.model.Usuario;

public interface UsuarioRepository  extends JpaRepository<Usuario, Long>{

    Optional<Usuario> findBySenhaAndEmail(String email, String senha);
    
}
