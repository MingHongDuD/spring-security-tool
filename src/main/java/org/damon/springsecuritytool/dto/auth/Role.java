package org.damon.springsecuritytool.dto.auth;

import org.springframework.security.core.GrantedAuthority;

/**
 * @author damon 20250521
 */
public enum Role implements GrantedAuthority {
    ADMIN, USER;

    @Override
    public String getAuthority() {
        return name();
    }
}
