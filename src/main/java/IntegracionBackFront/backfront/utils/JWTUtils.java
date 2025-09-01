package IntegracionBackFront.backfront.utils;

import com.google.api.client.util.Value;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

@Component
public class JWTUtils {

        @Value("${security.jwt.secret}")
        private String jwtSecreto;

        @Value("${security.jwt.issuer}")
        private String issuer;

        @Value("${security.jwt.expiration}")
        private long expirationMS;
        private final Logger log = LoggerFactory.getLogger(JWTUtils.class);

        public String create(String id, String correo, String rol){
                //Decodificar el secreto Base64 y crea una clave HMAC-SHA segura
                SecretKey signingKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecreto));

                //Obtener la fecha actual y calcular la fecha de expiracion
                Date now = new Date();
                Date expiration = new Date(now.getTime() + expirationMS);

                //Construir el token con sus componentes
                return Jwts.builder()
                        .setId(id)   //ID del token
                        .setIssuedAt(now) // Fecha de emsion
                        .setSubject(correo) //Sujeto
                        .setIssuer(issuer)//Emisor del token
                        .setExpiration(expirationMS >= 0 ? expiration : null) //Tiempo de expiracion
                        .signWith(signingKey, SignatureAlgorithm.HS256) //Firma del agoritmo HS256
                        .compact();   //Convierte a String compacto
        }

        public String getValue(String jwt){
                Claims claims = parseClaims(jwt);
                return  claims.getSubject();

        }

        public Claims parseToken(String jwt)throws ExpiredJwtException, MalformedJwtException{
                return parseClaims(jwt);
        }

        public String extractTokenFromRequest(HttpServletRequest request){
                Cookie[] cookies = request.getCookies();
                if (cookies != null){
                        for (Cookie cookie : cookies){
                                if (cookie.getName().equals("authToken")){
                                        return  cookie.getValue();
                                }
                        }
                }
                return null;
        }

        public  boolean validate(String token){
                try {
                        parseClaims(token);
                        return true;
                }catch (JwtException | IllegalArgumentException e){
                        log.warn("Token invalido: {}", e.getMessage());
                        return false;
                }
        }

        private Claims parseClaims(String jwt) {
                //Configurar el parse con la clave de firma y parsea el token
                return  Jwts.parserBuilder()
                        .setSigningKey(Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecreto)))
                        .build()
                        .parseClaimsJwt(jwt)
                        .getBody();
        }


}
