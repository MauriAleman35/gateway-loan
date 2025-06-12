package erpgateway.demo.filters;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpRequestDecorator;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Component
public class GraphQLJWTFilter implements GlobalFilter, Ordered {
    private static final Logger log = LoggerFactory.getLogger(GraphQLJWTFilter.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${jwt.security.key}")
    private String SECRET_KEY;

    private SecretKey key;

    // Operaciones que no requieren autenticación
    private final Set<String> publicOperations = new HashSet<>(
            Arrays.asList("login", "register", "introspection", "__schema")
    );

    @PostConstruct
    public void init() {
        if (SECRET_KEY == null || SECRET_KEY.isEmpty()) {
            throw new IllegalStateException("La clave secreta (jwt.security.key) no está configurada.");
        }
        this.key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
        log.info("Filtro GraphQL JWT inicializado con {} operaciones públicas", publicOperations.size());
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getPath().toString();

        // Solo procesar solicitudes GraphQL
        if (!path.contains("/graphql")) {
            return chain.filter(exchange);
        }
        // Excluir solicitudes a la ruta BI externa
        if (path.startsWith("/bi")) {
            return chain.filter(exchange);
        }
        // Verificar si es una solicitud al servicio ML
        boolean isMLRequest = path.contains("/ml/graphql");

        // Permitir OPTIONS para preflight CORS
        if (request.getMethod().equals(HttpMethod.OPTIONS)) {
            log.debug("Preflight OPTIONS request, permitiendo sin validación JWT");
            return chain.filter(exchange);
        }

        log.debug("Procesando solicitud GraphQL: {} (ML Service: {})", path, isMLRequest);

        // Leer y analizar el cuerpo de la solicitud
        return DataBufferUtils.join(exchange.getRequest().getBody())
                .flatMap(dataBuffer -> {
                    try {
                        // Leer el contenido del cuerpo
                        byte[] bytes = new byte[dataBuffer.readableByteCount()];
                        dataBuffer.read(bytes);
                        DataBufferUtils.release(dataBuffer);

                        String body = new String(bytes, StandardCharsets.UTF_8);
                        JsonNode requestBody = objectMapper.readTree(body);

                        // Verificar si es una operación pública
                        if (requestBody.has("query")) {
                            String query = requestBody.get("query").asText();

                            // Verificar si la operación es pública
                            if (isPublicOperation(query)) {
                                log.info("Operación GraphQL pública detectada, permitiendo sin token");
                                return rewriteRequest(exchange, chain, body);
                            }

                            // No es una operación pública, verificar el token JWT
                            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                                log.warn("Token no proporcionado para operación protegida");
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

                                log.debug("JWT válido para el usuario: {}", claims.getSubject());

                                // NUEVA LÓGICA: Si es una solicitud al servicio ML, verificar rol USER
                                if (isMLRequest) {
                                    // Obtener los roles del token
                                    List<String> roles = claims.get("roles", List.class);

                                    // Para ML solo requerimos ROLE_USER
                                    if (roles != null && roles.contains("ROLE_USER")) {
                                        log.debug("Usuario con ROLE_USER accediendo a ML service, permitido");
                                        return rewriteRequest(exchange, chain, body);
                                    } else {
                                        log.warn("Acceso denegado a ML service: se requiere ROLE_USER");
                                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                                        return exchange.getResponse().setComplete();
                                    }
                                }

                                // Para otras solicitudes, continuar normalmente
                                return rewriteRequest(exchange, chain, body);

                            } catch (Exception e) {
                                log.error("Error al validar el token JWT: {}", e.getMessage());
                                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                return exchange.getResponse().setComplete();
                            }
                        }

                        // Si no hay query, continuar por defecto
                        return rewriteRequest(exchange, chain, body);

                    } catch (Exception e) {
                        log.error("Error al procesar solicitud GraphQL", e);
                        exchange.getResponse().setStatusCode(HttpStatus.BAD_REQUEST);
                        return exchange.getResponse().setComplete();
                    }
                });
    }

    private boolean isPublicOperation(String query) {
        query = query.toLowerCase();

        // Verificar si contiene alguna operación pública
        for (String operation : publicOperations) {
            if (query.contains(operation)) {
                return true;
            }
        }

        // También permitir consultas de introspección (para herramientas como GraphiQL)
        if (query.contains("__schema") || query.contains("__type")) {
            return true;
        }

        return false;
    }

    private Mono<Void> rewriteRequest(ServerWebExchange exchange, GatewayFilterChain chain, String body) {
        // Recrear el cuerpo de la solicitud
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);

        // Crear una solicitud decorada con el mismo cuerpo
        ServerHttpRequestDecorator decorator = new ServerHttpRequestDecorator(exchange.getRequest()) {
            @Override
            public Flux<DataBuffer> getBody() {
                DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(bytes);
                return Flux.just(buffer);
            }
        };

        // Continuar con la solicitud modificada
        return chain.filter(exchange.mutate().request(decorator).build());
    }

    @Override
    public int getOrder() {
        return -90; // Alta prioridad, pero después de CORS si existe
    }
}