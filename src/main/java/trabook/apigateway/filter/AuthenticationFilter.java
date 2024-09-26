package trabook.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.crypto.Commitment;
import org.json.JSONObject;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;
import java.util.Map;

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
            // JWT 토큰을 .으로 구분된 세 부분으로 나누기
            String[] tokenParts = accessToken.split("\\.");
            byte[] decodedBytes = Base64.getDecoder().decode(tokenParts[1]);
            String decodedString = new String(decodedBytes);
            JSONObject jsonObject = new JSONObject(decodedString);
            Integer tempUserId = jsonObject.getInt("userId");
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
                //return onError(exchange, "Invalid JWT signature", HttpStatus.UNAUTHORIZED);
                return renewTokenAndContinue(exchange, chain, tempUserId, config);
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

    private Mono<Void> renewTokenAndContinue(ServerWebExchange exchange, GatewayFilterChain chain, Integer userId, Config config) {
        WebClient webClient = WebClient.builder().baseUrl("http://34.118.151.117:4060").build(); // auth-service URL
        log.info("start renewTokenAndContinue");
        log.info("userId={}", userId);
        return webClient.get()
                .uri("/auth/renew-token")
                .header("userId", userId.toString())
                .retrieve()
                .toEntity(Map.class) // 응답을 엔티티로 받아 헤더와 바디 모두 처리
                .flatMap(responseEntity -> {
                    // Authorization 헤더 값 추출

                    String newAccessToken = responseEntity.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

                    // 새로운 토큰이 없을 경우 에러 처리
                    if (newAccessToken == null || newAccessToken.isEmpty()) {
                        log.error("Failed to receive a valid token from /auth/renew-token.");
                        return onError(exchange, "Failed to renew JWT token", HttpStatus.UNAUTHORIZED);
                    }
                    String secretString = config.getSecret();
                    SecretKey key = Keys.hmacShaKeyFor(secretString.getBytes());
                    Claims claims = Jwts.parser()
                            .setSigningKey(key)
                            .build()
                            .parseClaimsJws(newAccessToken)
                            .getBody();

                    Integer newUserId = claims.get("userId", Integer.class);
                    Date issuedAt = claims.getIssuedAt();
                    Date notBefore = claims.getNotBefore();
                    Date expiration = claims.getExpiration();
                    // userId 헤더에 newUserId 추가
                    ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                            .header("userId", newUserId.toString()) // newUserId를 헤더에 추가
                            .build();

                    // 최종 응답에 Authorization 헤더로 갱신된 토큰 추가
                    exchange.getResponse().getHeaders().add(HttpHeaders.AUTHORIZATION, newAccessToken);

                    // 새로운 요청으로 교체
                    ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();

                    // 체인 필터로 이어서 처리
                    return chain.filter(mutatedExchange);
                })
                .onErrorResume(e -> {
                    log.error("Error while renewing JWT token: {}", e.getMessage());
                    return onError(exchange, "Error renewing JWT token", HttpStatus.UNAUTHORIZED);
                });
    }
}