package org.damon.springsecuritytool.auth;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.damon.springsecuritytool.exception.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * JWT 过滤器，拦截每个 HTTP 请求，验证 JWT 令牌并设置认证上下文。
 * OncePerRequestFilter 确保过滤器在每个请求中只执行一次
 *
 * @author damon 20250521
 */
public class JwtTokenFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtTokenFilter.class);
    private final JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException {
        try {
            String token = jwtTokenProvider.resolveToken(request);
            if (token != null && jwtTokenProvider.validateToken(token)) {
                Authentication auth = jwtTokenProvider.getAuthentication(token);
                SecurityContextHolder.getContext().setAuthentication(auth);
                logger.debug("JWT authentication successful for request: {}", request.getRequestURI());
            } else {
                logger.debug("No valid JWT token found for request: {}", request.getRequestURI());
            }
            filterChain.doFilter(request, response);
        } catch (ValidationException e) {
            logger.error("JWT validation failed: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Invalid or expired JWT token\", \"message\": \"" + e.getMessage() + "\"}");
        } catch (Exception e) {
            logger.error("Unexpected error during JWT processing: {}", e.getMessage(), e);
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Internal server error\", \"message\": \"Unexpected error occurred\"}");
        }
    }
}