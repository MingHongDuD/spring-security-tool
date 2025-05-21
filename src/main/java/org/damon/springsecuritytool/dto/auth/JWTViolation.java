package org.damon.springsecuritytool.dto.auth;

/**
 * @author damon 20250521
 */
public class JWTViolation extends Violation {
    public JWTViolation(String code, String message) {
        super(code, message);
    }
}
