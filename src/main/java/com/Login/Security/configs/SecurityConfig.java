package com.Login.Security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.SecurityBuilder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.WebSecurityConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
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
            .requestMatchers("/login").authenticated()
            .anyRequest().authenticated())
        .formLogin(login -> login
            .loginPage("/login")
            .usernameParameter("email")
            .passwordParameter("senha")
            .permitAll()
            .successHandler(authenticationSuccessHandler())
            .failureHandler(authenticationFailureHandler()));
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
  public UserDetailsService userDetailsService() {
    PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);

    UserDetails user = User.builder()
        .username("email")
        .password(passwordEncoder.encode("senha"))
        .roles("USER")
        .build();

    return new InMemoryUserDetailsManager(user);
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  AuthenticationSuccessHandler authenticationSuccessHandler() {
    return new CustomAuthenticationSuccessHandler();
  }

  @Bean
  AuthenticationFailureHandler authenticationFailureHandler() {
    return new CustomAuthenticationFailureHandler();
  }

}
