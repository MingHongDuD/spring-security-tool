package org.damon.springsecuritytool.config;

import org.damon.springsecuritytool.auth.JwtTokenFilter;
import org.damon.springsecuritytool.auth.JwtTokenProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * @author damon 20250521
 */
@Configuration
@EnableWebSecurity // 启用 Spring Security：激活安全过滤链，允许自定义认证和授权规则，配合 SecurityFilterChain 定义安全策略
@EnableMethodSecurity() // 启动方法级的安全注解支持
public class WebSecurityConfig {

    private static final String[] PUBLIC_ENDPOINTS = {
            "/registerSession", "/_health",
            "/swagger-resources/**", "/webjars/**",
            "/v2/**", "/swagger-ui.html/**", "/error"
    };
    /**
     * 注入，用于处理 JWT 令牌的生成、验证和解析
     */
    private final JwtTokenProvider jwtTokenProvider;
    /**
     * 从配置文件读取允许的跨域来源，控制哪些前端域名可以访问后端
     */
    @Value("${cors.allowed.origins}")
    private String[] allowedOrigins;

    public WebSecurityConfig(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * 配置安全过滤链，定义哪些 URL 需要认证和授权
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 配置URL访问权限
                .authorizeHttpRequests(auth -> auth
                        // 公开以下接口，用来登陆、健康检查或文档访问，对所有人开放
                        .requestMatchers(PUBLIC_ENDPOINTS).permitAll()
                        // 仅角色 ADMIN 可以访问 /admin/**
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        // 仅角色 USER 可以访问 /user/**
                        .requestMatchers("/user/**").hasRole("USER")
                        // 除了上述规则，其他请求都需要认证（就是必须携带有效的JWT令牌）
                        .anyRequest().authenticated()
                )
                // 配置安全头
                .headers(headers -> headers
                        // 禁用默认的 HTTP 头
                        .defaultsDisabled()
                        // 添加缓存控制头，防止浏览器缓存敏感响应，提高安全。
                        .addHeaderWriter(new CacheControlHeadersWriter())
                        // 防止点击劫持
                        .frameOptions(HeadersConfigurer.FrameOptionsConfig::deny)
                )
                // 禁用 CSRF-跨站请求伪造 保护，允许所有请求，忽略 CSRF 检查
                .csrf(csrf -> csrf.ignoringRequestMatchers("/**"))
                // 启用 CORS-跨域资源共享，使用 corsConfigurationSource 定义的配置
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // 在 Spring Security 的默认用户名密码过滤器之前添加自定义的 JwtTokenFilter。
                // JwtTokenFilter 负责从请求头提取 JWT 令牌，验证有效性，并设置 SecurityContextHolder 的认证信息。
                .addFilterBefore(new JwtTokenFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /**
     * 针对跨域进行配置
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // 指定允许的跨域来源
        configuration.setAllowedOrigins(Arrays.asList(allowedOrigins));
        // 允许的 HTTP 方法
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
        // 允许所有请求头（如 Authorization、Content-Type）。
        configuration.setAllowedHeaders(List.of("*"));
        // 允许发送凭据（如 cookie、Authorization 头）。支持携带 JWT 令牌的请求，但需确保 allowedOrigins 不为 *。
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        // 将 CORS 配置应用于所有路径（/**），所有接口都遵循此 CORS 规则。
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    /**
     * 定义 HTTP 防火墙，限制允许的 HTTP 方法，防止非法请求。
     */
    @Bean
    public HttpFirewall httpFirewall() {
        // 使用 StrictHttpFirewall，提供严格的请求过滤，防止恶意请求（如路径穿越、非法字符）。
        StrictHttpFirewall strictHttpFirewall = new StrictHttpFirewall();
        Set<String> allowedHttpMethods = new HashSet<>();
        // 允许 GET、HEAD、POST、PUT、PATCH、DELETE、OPTIONS 和 TRACE 方法。
        allowedHttpMethods.add(HttpMethod.GET.name());
        allowedHttpMethods.add(HttpMethod.HEAD.name());
        allowedHttpMethods.add(HttpMethod.POST.name());
        allowedHttpMethods.add(HttpMethod.PUT.name());
        allowedHttpMethods.add(HttpMethod.PATCH.name());
        allowedHttpMethods.add(HttpMethod.DELETE.name());
        allowedHttpMethods.add(HttpMethod.OPTIONS.name());
        // TRACE 方法 可能存在问题
        allowedHttpMethods.add(HttpMethod.TRACE.name());
        strictHttpFirewall.setAllowedHttpMethods(allowedHttpMethods);
        return strictHttpFirewall;
    }
}
