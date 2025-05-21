package org.damon.springsecuritytool.auth;


import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import org.damon.springsecuritytool.dto.auth.JWTViolation;
import org.damon.springsecuritytool.dto.auth.JwtUserInfo;
import org.damon.springsecuritytool.exception.ValidationException;
import org.damon.springsecuritytool.util.JwtUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * JWT 令牌提供者，负责生成、解析和验证 JWT 令牌。
 *
 * @author damon 20250521
 */
@Component
public class JwtTokenProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    private static final String BEARER_PREFIX = "Bearer ";
    private final ObjectMapper objectMapper;
    /**
     * 用于签名和验证 JWT 的密钥（实际生产中应使用配置中心）
     */
    @Value("${security.jwt.token.secret-key:secret-key}")
    private String secretKey;
    /**
     * 从配置文件读取 JWT 令牌的有效期（毫秒），默认1小时
     */
    @Value("${security.jwt.token.expire-length:3600000}")
    private long validityInMilliseconds = 3600000;
    /**
     * 存储解码后的密钥
     */
    private byte[] keyBytes;

    public JwtTokenProvider(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * 在初始化之后，设置密钥的算法
     */
    @PostConstruct
    protected void init() {
        try {
            this.keyBytes = java.util.Base64.getDecoder().decode(secretKey);
            logger.info("Initialized JWT secret key");
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Invalid Base64-encoded JWT secret key", e);
        }
    }

    /**
     * 从 HTTP 请求的 Authorization Head 提取 JWT 令牌。
     */
    public String resolveToken(HttpServletRequest request) {
        if (request == null) {
            logger.warn("Received null HttpServletRequest");
            return null;
        }
        String bearerToken = request.getHeader("Authorization");
        if (!StringUtils.hasText(bearerToken) || !bearerToken.startsWith(BEARER_PREFIX)) {
            logger.debug("No valid Bearer token found in Authorization header");
            return null;
        }
        String token = bearerToken.substring(BEARER_PREFIX.length());
        logger.debug("Extracted JWT token");
        return token;
    }

    /**
     * 根据 JwtUserInfo 生成一个新的 JWT 令牌。
     */
    public String createToken(JwtUserInfo jwtUserInfo) {
        if (jwtUserInfo == null || !StringUtils.hasText(jwtUserInfo.getUserId())) {
            logger.error("Invalid JwtUserInfo provided for token creation");
            throw new IllegalArgumentException("JwtUserInfo or userId cannot be null/empty");
        }

        Instant now = Instant.now();
        Instant expiry = now.plusMillis(validityInMilliseconds);

        Algorithm algorithm;
        int bitLength = keyBytes.length * 8;
        if (bitLength >= 512) {
            algorithm = Algorithm.HMAC512(keyBytes);
        } else if (bitLength >= 384) {
            algorithm = Algorithm.HMAC384(keyBytes);
        } else {
            algorithm = Algorithm.HMAC256(keyBytes);
        }

        String token = JWT.create()
                .withSubject(jwtUserInfo.getUserId())
                .withClaim("jwtUserInfo", objectMapper.convertValue(jwtUserInfo, Map.class))
                .withIssuedAt(Date.from(now))
                .withExpiresAt(Date.from(expiry))
                .sign(algorithm);

        logger.info("Create JWT token for user: {}", jwtUserInfo.getUserId());
        return token;
    }

    /**
     * 刷新令牌，延长用户会话时间
     */
    public String refreshToken() {
        JwtUserInfo userInfo = getJwtUserInfo();
        return createToken(userInfo);
    }

    /**
     * 根据 JWT 令牌生成 spring security 的 Authentication 对象
     */
    public Authentication getAuthentication(String token) {
        if (!StringUtils.hasText(token)) {
            logger.error("Token is null or empty");
            throw new IllegalArgumentException("Token cannot be null or empty");
        }

        // 解析令牌中的用户信息
        JwtUserInfo jwtUserInfo = getJwtUserInfo(token);
        // 根据 spring security 内置 user，构建一个 user 对象
        return new CustomUsernamePasswordAuthenticationToken(
                org.springframework.security.core.userdetails.User
                        .withUsername(jwtUserInfo.getUserId())
                        .password("")
                        .authorities(jwtUserInfo.getRoleList())
                        .accountExpired(false)
                        .accountLocked(false)
                        .credentialsExpired(false)
                        .disabled(false)
                        .build(),
                "",
                jwtUserInfo.getRoleList(),
                jwtUserInfo);
    }

    /**
     * 从 Spring Security 的上下文获取当前的认证的 JwtUserInfo
     */
    public JwtUserInfo getJwtUserInfo() {
        // 从 SecurityContextHolder 中获取当前认证对象。
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof CustomUsernamePasswordAuthenticationToken)) {
            logger.error("Invalid authentication type in SecurityContext");
            throw new IllegalStateException("No valid authentication found");
        }
        return ((CustomUsernamePasswordAuthenticationToken) authentication).getJwtUserInfo();
    }

    /**
     * 解析令牌中的用户信息( JwtUserInfo )
     */
    private JwtUserInfo getJwtUserInfo(String token) {
        try {
            // 解析 JWT 令牌，获取声明 claims
            Map<String, Object> claims = extractJwtClaims(token);
            // 提取出 JwtUserInfo 字段
            return objectMapper.convertValue(claims.get("jwtUserInfo"), JwtUserInfo.class);
        } catch (Exception e) {
            logger.error("Failed to parse JwtUserInfo from token: {}", token);
            throw new ValidationException(
                    List.of(new JWTViolation("", "Failed to parse JwtUserInfo: " + e.getMessage())),
                    ValidationException.Type.INBOUND_REQUEST);
        }
    }

    /**
     * 验证 JWT 令牌的有效性
     */
    public boolean validateToken(String token) {
        try {
            if (!StringUtils.hasText(token)) {
                logger.error("Token is null or empty");
                throw new IllegalArgumentException("Token cannot be null or empty");
            }
            if (!JwtUtils.isJwtFormat(token)) {
                logger.error("Invalid JWT format");
                throw new IllegalArgumentException("Invalid JWT format");
            }
            // 验证通过 extractJwtClaims 完成
            extractJwtClaims(token);
            logger.debug("JWT token validated successfully");
            return true;
        } catch (Exception e) {
            throw new ValidationException(
                    List.of(new JWTViolation("", "Expired or invalid JWT token: " + e.getMessage())),
                    ValidationException.Type.INBOUND_REQUEST);
        }
    }

    /**
     * 从 JWT 令牌中提取声明 claims
     */
    public Map<String, Object> extractJwtClaims(String token) throws JWTVerificationException {
        // 解析令牌头部获取算法，不验证，仅解析头部
        DecodedJWT jwt = JWT.decode(token);
        String algorithm = jwt.getAlgorithm();

        // 根据算法选择对应的 HMAC 算法
        Algorithm algo = switch (algorithm) {
            case "HS256" -> Algorithm.HMAC256(keyBytes);
            case "HS384" -> Algorithm.HMAC384(keyBytes);
            case "HS512" -> Algorithm.HMAC512(keyBytes);
            default -> {
                logger.error("Unsupported JWT algorithm: {}", algorithm);
                throw new JWTVerificationException("Unsupported algorithm: " + algorithm);
            }
        };

        // 配置验证器
        JWTVerifier verifier = JWT.require(algo)
                .build();

        // 验证并提取声明
        jwt = verifier.verify(token);
        logger.debug("Extracted claims for token with subject: {}", jwt.getSubject());
        return jwt.getClaims().entrySet().stream()
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        entry -> entry.getValue().as(Object.class)
                ));
    }
}
