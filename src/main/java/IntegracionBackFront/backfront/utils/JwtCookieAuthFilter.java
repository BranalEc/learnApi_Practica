package IntegracionBackFront.backfront.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.coyote.Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

@Component
public class JwtCookieAuthFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtCookieAuthFilter.class);
    private static final String AUTH_COOKIE_NAME="authToken";
    private final JWTUtils jwtUtils;

    @Autowired
    public JwtCookieAuthFilter(JWTUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getRequestURI().equals("/api/auth/login") ||
                request.getRequestURI().equals("/api/auth/register")){
            filterChain.doFilter(request, response);
            return;
        }
        try {
            //Extraer token JWT de las cookies de la solicitud
            String token = extractTokenFromCookies(request);

            if (token == null || token.isBlank()){
                sendError(response, "token no encontrado", HttpServletResponse.SC_UNAUTHORIZED);
                return;
            }
            Claims claims = jwtUtils.parseToken(token);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    claims.getSubject(),
                    null,
                    Arrays.asList(() -> "ROLE_USER")
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        }catch (ExpiredJwtException e){
            logger.warn("Token expirado: {}", e.getMessage());
            sendError(response, "Token expirado", HttpServletResponse.SC_UNAUTHORIZED);
        }
        catch (MalformedJwtException e){
            logger.warn("Token malformado: {}", e.getMessage());
            sendError(response, "Token invalido", HttpServletResponse.SC_FORBIDDEN);

        }
        catch (Exception e){
            logger.error("Error de autenticacion", HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
    private void sendError(HttpServletResponse response, String message, int status) throws IOException {
        response.setContentType("application/json");    // Establece el tipo de contenido
        response.setStatus(status);                     // Establece código de estado HTTP
        response.getWriter().write(String.format(
                "{\"error\": \"%s\", \"status\": %d}", message, status)); // Escribir respuesta JSON
    }

    private String extractTokenFromCookies(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null){
            return null;
        }
        return Arrays.stream(cookies)
                .filter(c-> AUTH_COOKIE_NAME.equals(c.getName()))
                .findFirst()
                .map(Cookie::getValue)
                .orElse(null);

    }

    private Collection<? extends GrantedAuthority> getAuthorities (String token){
        return Collections.emptyList();
    }
}
