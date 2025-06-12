package erpgateway.demo.filters;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.List;

@Component
public class CorsDeduplicationFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(CorsDeduplicationFilter.class);

    private static final List<String> CORS_HEADERS = Arrays.asList(
            HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN,
            HttpHeaders.ACCESS_CONTROL_ALLOW_METHODS,
            HttpHeaders.ACCESS_CONTROL_ALLOW_HEADERS,
            HttpHeaders.ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HttpHeaders.ACCESS_CONTROL_MAX_AGE
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return chain.filter(exchange).then(Mono.fromRunnable(() -> {
            HttpHeaders headers = exchange.getResponse().getHeaders();

            // Eliminar cabeceras duplicadas manteniendo solo la primera
            for (String headerName : CORS_HEADERS) {
                List<String> headerValues = headers.get(headerName);
                if (headerValues != null && headerValues.size() > 1) {
                    String firstValue = headerValues.get(0);
                    headers.set(headerName, firstValue);
                    log.debug("Deduplicado header CORS {}: {} valores -> 1 valor",
                            headerName, headerValues.size());
                }
            }
        }));
    }

    @Override
    public int getOrder() {
        // Ejecuta después de todos los filtros normales pero antes de enviar la respuesta
        return Ordered.LOWEST_PRECEDENCE - 1;
    }
}