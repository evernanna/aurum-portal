package me.aurum.config;

import lombok.extern.slf4j.Slf4j;
import me.aurum.security.JwtProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;

    public JwtAuthenticationFilter(JwtProvider jwtProvider) {
        this.jwtProvider = jwtProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        log.info(" request.getParameterMap :: {}", request.getParameterMap().toString());

        String username = request.getParameter("username");
        String account = request.getParameter("account");
        log.info(" username :: {}", username);
        log.info(" account :: {}", account);

        Map<String, String[]> parameterMap = request.getParameterMap();
        String[] headers = parameterMap.get("header");
        String[] bodies = parameterMap.get("body");
        String[] usernames = parameterMap.get("username");
        String[] accounts = parameterMap.get("account");

        log.info(" headers :: {}", headers);
        log.info(" bodies :: {}", bodies);
        log.info(" usernames :: {}", usernames);
        log.info(" accounts :: {}", accounts);

        String token = jwtProvider.resolveToken(request);

        if (token != null && jwtProvider.validateToken(token)) {
            token = token.split(" ")[1].trim();
            Authentication auth = jwtProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }
}
