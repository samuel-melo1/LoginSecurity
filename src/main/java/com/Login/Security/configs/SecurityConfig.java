package com.Login.Security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(requests -> requests
            .requestMatchers("/login").permitAll()
            .anyRequest().authenticated())
        .formLogin(login -> login.permitAll());
        http.formLogin(login -> login
                .defaultSuccessUrl("/home")
                .failureUrl("/login?error=true")
                .permitAll());
        http.formLogin(login -> login
                .loginPage("/login")
                .usernameParameter("email")
                .passwordParameter("passcode")
                .permitAll());
        http.formLogin(login -> login
                .successForwardUrl("/login_success_handler"));
        http.formLogin(login -> login
                .failureForwardUrl("/login_failure_handler"));
        http.formLogin(login -> login
                .successHandler(authenticationSuccessHandler())
                .failureHandler(authenticationFailureHandler()));
    return http.build();
}
    
  @Bean
  public UserDetailsService userDetailsService() {
    UserDetails user = User.builder()
        .username("user")
        .password(passwordEncoder().encode("password"))
        .roles("USER")
        .build();
    UserDetails admin = User.builder()
        .username("admin")
        .password(passwordEncoder().encode("password"))
        .roles("USER", "ADMIN")
        .build();
    return new InMemoryUserDetailsManager(user, admin);
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
