package trabook.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
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
            request.mutate().header("userId", "-1").build(); // userId 헤더 강제 초기화
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

            Integer userId = -1;
            try {
                String secretString = config.getSecret();
                SecretKey key = Keys.hmacShaKeyFor(secretString.getBytes());
                Claims claims = Jwts.parser()
                        .setSigningKey(key)
                        .build()
                        .parseClaimsJws(accessToken)
                        .getBody();
                userId = claims.get("userId", Integer.class);
                Date issuedAt = claims.getIssuedAt();
                Date notBefore = claims.getNotBefore();
                Date expiration = claims.getExpiration();
            } catch (ExpiredJwtException e) {
                log.error("JWT Token has expired: {}", e.getMessage());
                return onError(exchange, "JWT Token has expired", HttpStatus.UNAUTHORIZED);
            } catch (SignatureException e) {
                log.error("Invalid JWT signature: {}", e.getMessage());
                return onError(exchange, "Invalid JWT signature", HttpStatus.UNAUTHORIZED);
            } catch (Exception e) {
                log.error("Invalid JWT token: {}", e.getMessage());
                return onError(exchange, "Invalid JWT signature", HttpStatus.UNAUTHORIZED);
            }
            request.mutate().header("userId", userId.toString()).build();
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