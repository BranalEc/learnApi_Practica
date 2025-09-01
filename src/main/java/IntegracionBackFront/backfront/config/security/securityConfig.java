package IntegracionBackFront.backfront.config.security;

import IntegracionBackFront.backfront.utils.JwtCookieAuthFilter;
import org.apache.catalina.security.SecurityConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

public class securityConfig {
    private final JwtCookieAuthFilter jwtCookieAuthFilter;

    public securityConfig(JwtCookieAuthFilter jwtCookieAuthFilter) {
        this.jwtCookieAuthFilter = jwtCookieAuthFilter;
    }

    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        //Aqui van todos los endpoints publics que no requieren de un JWT
        http
                .csrf(csrf -> csrf.disable())

    }

}
