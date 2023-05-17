package com.Login.Security.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import com.Login.Security.model.Usuario;



@Repository
public interface UsuarioRepository  extends JpaRepository<Usuario, Long>{

    Optional<Usuario> findBySenhaAndEmail(String email, String senha);
    Optional<Usuario>  findByEmail(String email);
    
}
