
package com.Login.Security.configs;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request,
                                      HttpServletResponse response,
                                      Authentication authentication) throws IOException, ServletException {

      if (authentication.isAuthenticated()) {
          // Usuário autenticado com sucesso
          System.out.println("Usuário autenticado: " + authentication.getName());
          response.sendRedirect("/home"); // Redirecionar para a página inicial ou outra página desejada
      } else {
          // Falha na autenticação
          System.out.println("Falha na autenticação");
      }
  }
}
