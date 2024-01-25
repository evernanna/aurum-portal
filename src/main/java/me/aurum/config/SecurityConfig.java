package me.aurum.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import me.aurum.security.JwtProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true, prePostEnabled = true)
@Slf4j
public class SecurityConfig {

    private final JwtProvider jwtProvider;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity security) throws Exception {

        security
                // ID, Password 문자열을 Base64로 인코딩하여 전달하는 구조
                //.httpBasic().disable()
                // 쿠키 기반이 아닌 JWT 기반이므로 사용하지 않음
                .csrf().disable()
                // CORS 설정
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
                // Spring Security 세션 정책 : 세션을 생성 및 사용하지 않음
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // 조건별로 요청 허용/제한 설정
                .authorizeRequests()
                .antMatchers("/api/login/**").permitAll()
                .antMatchers("/api/login/signin").permitAll()
                //.antMatchers("/").permitAll()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/user/**").hasRole("USER")

                //.anyRequest().denyAll()
                .and()
                // JWT 인증 필터 적용
                .addFilterBefore(new JwtAuthenticationFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class)
                // 에러 핸들링
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
    }

}
