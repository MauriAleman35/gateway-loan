package erpgateway.demo.filters;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.List;

@Component
public class FilterApi implements GlobalFilter, Ordered {
    private static final Logger log = LoggerFactory.getLogger(FilterApi.class);

    @Value("${jwt.security.key}")
    private String SECRET_KEY;

    private SecretKey key;

    @PostConstruct
    public void init() {
        if (SECRET_KEY == null || SECRET_KEY.isEmpty()) {
            throw new IllegalStateException("La clave secreta (jwt.security.key) no está configurada.");
        }
        this.key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        log.info("Filtro REST API inicializado");
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().toString();

        // Solo procesar rutas de API REST específicas
        if (!path.startsWith("/api/verify-")) {
            return chain.filter(exchange);
        }

        log.debug("Procesando solicitud REST API: {}", path);

        // Verificar el token JWT
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.warn("Token no proporcionado para operación protegida: {}", path);
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }

        String token = authHeader.substring(7);

        try {
            // Validar el token
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            // Obtener los roles del token
            List<String> roles = claims.get("roles", List.class);

            // Para endpoints de verificación, requerir ROLE_USER
            if (roles != null && roles.contains("ROLE_USER")) {
                log.debug("Usuario con ROLE_USER accediendo a {}, permitido", path);
                return chain.filter(exchange);
            } else {
                log.warn("Acceso denegado a {}: se requiere ROLE_USER", path);
                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                return exchange.getResponse().setComplete();
            }

        } catch (Exception e) {
            log.error("Error al validar el token JWT: {}", e.getMessage());
            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getResponse().setComplete();
        }
    }

    @Override
    public int getOrder() {
        // Ejecutar antes que otros filtros
        return -100;
    }
}