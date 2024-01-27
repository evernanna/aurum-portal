package me.aurum.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.aurum.define.UserAuthority;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Slf4j
public class SecurityConfig {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring()
                .antMatchers("/assets/**");
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf().disable();

        httpSecurity
                .authorizeRequests()
                .antMatchers("/login", "/signup").permitAll()
                .antMatchers("/api/**").permitAll()
                .antMatchers("/test").permitAll()
                .antMatchers("/master/**").hasRole(UserAuthority.ROLE_MASTER.getCode())
                .antMatchers("/admin/**").hasRole(UserAuthority.ROLE_ADMIN.getCode())
                .anyRequest().authenticated();

        httpSecurity
                .formLogin() // Form Login 설정
                .usernameParameter("account")
                .passwordParameter("password")
                .loginPage("/login")
                .loginProcessingUrl("/login-proc")
                .successHandler( // 로그인 성공 후 핸들러
                        new AuthenticationSuccessHandler() {
                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                log.warn("Authentication: {}", authentication.getName());
                                response.sendRedirect("/main");
                            }

                            @Override
                            public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
                                AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain, authentication);
                            }
                        })
                .failureHandler( // 로그인 실패 후 핸들러
                        new AuthenticationFailureHandler() { // 익명 객체 사용
                            @Override
                            public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                log.error("Exception: {}", exception.getMessage());
                                response.sendRedirect("/login");
                            }
                        })
                .and()
                .logout();

        return httpSecurity.build();
    }
}

    /*@Bean
    public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {

        security
                .csrf().disable()
                .cors(c -> {
                            CorsConfigurationSource source = request -> {
                                // Cors 허용 패턴
                                CorsConfiguration config = new CorsConfiguration();
                                config.setAllowedOrigins(Arrays.asList("*"));
                                config.setAllowedMethods(Arrays.asList("*"));
                                return config;
                            };
                            c.configurationSource(source);
                        }
                )
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/api/login/**").permitAll()
                .antMatchers("/api/login/signin").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasRole("USER")

                .and()
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling()
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException, IOException {
                        // 권한 문제가 발생했을 때 이 부분을 호출한다.
                        response.setStatus(403);
                        response.setCharacterEncoding("utf-8");
                        response.setContentType("text/html; charset=UTF-8");
                        response.getWriter().write("권한이 없는 사용자입니다.");
                    }
                })
                .authenticationEntryPoint(new AuthenticationEntryPoint() {
                    @Override
                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
                        // 인증문제가 발생했을 때 이 부분을 호출한다.
                        response.setStatus(401);
                        response.setCharacterEncoding("utf-8");
                        response.setContentType("text/html; charset=UTF-8");
                        response.getWriter().write("인증되지 않은 사용자입니다.");
                    }
                });

        security.formLogin(
                formLogin -> formLogin.loginPage("/login-form")
                        //.usernameParameter("account")
                        //.passwordParameter("password")
                        //.loginProcessingUrl("/login-proc")
                        //.defaultSuccessUrl("/") //-> 성공시 이동할 url (이외에 추가 처리사항이 있으면 핸들러로 보내도 됨)
                        .successHandler( // 로그인 성공 후 핸들러
                                new AuthenticationSuccessHandler() {
                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                                        log.warn("authentication: {}",  authentication.getName());
                                        response.sendRedirect("/login-success");
                                    }

                                    @Override
                                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
                                        AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain, authentication);
                                    }
                                })
                        .failureHandler( // 로그인 실패 후 핸들러
                                new AuthenticationFailureHandler() { // 익명 객체 사용
                                    @Override
                                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                                        log.error("exception: {}",  exception.getMessage());
                                        response.sendRedirect("/login-form");
                                    }
                                })
        );

        return security.build();
    }*/
