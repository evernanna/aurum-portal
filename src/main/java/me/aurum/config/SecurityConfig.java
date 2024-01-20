package me.aurum.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {

        security.csrf().disable()
                .headers().frameOptions().disable();

        security.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        /*security.authorizeHttpRequests()
                //.antMatchers("/admin").hasRole("ROLE_ADMIN")
                .antMatchers("/h2-console/**").permitAll()
                .antMatchers("/login").permitAll()
                .anyRequest().authenticated();*/

        //security.formLogin().disable();
        //security.httpBasic().disable();
        return security.build();
    }

}
