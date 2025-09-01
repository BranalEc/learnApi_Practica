package IntegracionBackFront.backfront.config.app;

import IntegracionBackFront.backfront.utils.JWTUtils;
import IntegracionBackFront.backfront.utils.JwtCookieAuthFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class appConfig {

    @Bean
    public JwtCookieAuthFilter jwtCookieAuthFilter(JWTUtils jwtUtils){
        return new JwtCookieAuthFilter(jwtUtils);
    }
}
