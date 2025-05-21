package org.damon.springsecuritytool.auth;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.damon.springsecuritytool.dto.auth.JwtUserInfo;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.io.Serial;
import java.util.Collection;

/**
 * @author damon 20250521
 */
@Getter
@EqualsAndHashCode(callSuper = false)
public class CustomUsernamePasswordAuthenticationToken extends UsernamePasswordAuthenticationToken {

    @Serial
    private static final long serialVersionUID = 1L;

    private final JwtUserInfo jwtUserInfo;

    public CustomUsernamePasswordAuthenticationToken(Object principal, Object credentials,
                                                     Collection<? extends GrantedAuthority> authorities, JwtUserInfo jwtUserInfo) {
        super(principal, credentials, authorities);
        this.jwtUserInfo = jwtUserInfo;
    }

}
