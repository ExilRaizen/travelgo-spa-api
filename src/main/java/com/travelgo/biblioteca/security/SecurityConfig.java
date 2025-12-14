package com.travelgo.biblioteca.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .csrf(AbstractHttpConfigurer::disable)              //  CSRF off (clave para POST)
            .cors(Customizer.withDefaults())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                //  Permitir login (POST) explícito
                .requestMatchers(HttpMethod.POST, "/auth/login").permitAll()
                //  Permitir todo /auth por si agregas register/me/etc
                .requestMatchers("/auth/**").permitAll()
                .requestMatchers("/error").permitAll()
                //  Paquetes visibles sin token
                .requestMatchers(HttpMethod.GET, "/api/packages/**").permitAll()

                // Swagger + H2
                .requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/doc/**", "/h2-console/**").permitAll()

                .anyRequest().authenticated()
            )
            .headers(h -> h.frameOptions(f -> f.disable()))
            .formLogin(AbstractHttpConfigurer::disable)         //  sin /login
            .httpBasic(AbstractHttpConfigurer::disable);

        return http.build();
    }
}
