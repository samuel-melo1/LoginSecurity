package com.Login.Security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import com.Login.Security.service.CustomUserDetailsService;


@Configuration
@EnableWebSecurity
public class SecurityConfig {

  private CustomUserDetailsService userDetailsService;

  public SecurityConfig(CustomUserDetailsService userDetailsService) {
    this.userDetailsService = userDetailsService;
  }

  @Bean
  public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
        .authorizeHttpRequests(requests -> requests
            .requestMatchers("/login").permitAll()
            .requestMatchers("/cadastrar").permitAll()
            .requestMatchers("/home").authenticated()
            .anyRequest().authenticated())
        .formLogin(login -> login
            .loginPage("/login")
            .defaultSuccessUrl("/home")
            .usernameParameter("email")
            .passwordParameter("senha")
            .permitAll());
            
    return http.build();
  }

  @Bean
  public AuthenticationManager authenticationManager() throws Exception {
    return authentication -> {
      UserDetails userDetails = userDetailsService.loadUserByUsername(authentication.getName());
      if (userDetails != null
          && passwordEncoder().matches(authentication.getCredentials().toString(), userDetails.getPassword())) {
        return new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
      }
      throw new BadCredentialsException("Usuário inexistente ou senha inválida");
    };
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

}
