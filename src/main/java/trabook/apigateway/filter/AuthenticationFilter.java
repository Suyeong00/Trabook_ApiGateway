package trabook.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Date;

@Slf4j
@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {
     // 상속하고 있는 부모 AbstractGatewayFilterFactory 에게 Config.class 를 넘겨준다.

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            ServerHttpResponse response = exchange.getResponse();

            // Authorization 헤더 없으면 검증하지 않음
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                log.info("Not authorized request");
                return chain.filter(exchange);
            }

            // Authorization 헤더에서 가져오기
            String accessToken = request.getHeaders().getFirst("Authorization");

            if (accessToken == null || accessToken.isEmpty()) {
                log.error("JWT Token is missing or empty");
                return onError(exchange, "JWT Token is missing or empty", HttpStatus.UNAUTHORIZED);
            }

            String secretString = config.getSecret();
            SecretKey key = Keys.hmacShaKeyFor(secretString.getBytes());
            Claims claims = Jwts.parser()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();
            String userId = claims.get("userId", String.class);
            Date issuedAt = claims.getIssuedAt();
            Date notBefore = claims.getNotBefore();
            Date expiration = claims.getExpiration();

            request.mutate().header("userId", userId).build();
            log.info("login user: {}", userId);

            return chain.filter(exchange);
        };
    }

    private Mono<Void> onError(ServerWebExchange exchange, String errorMsg, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        log.error("onError: {}", errorMsg);
        return response.setComplete();
    }

    @Data
    public static class Config {
        private String secret;
    }
}