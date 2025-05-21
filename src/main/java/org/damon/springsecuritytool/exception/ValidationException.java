package org.damon.springsecuritytool.exception;

import lombok.Getter;
import org.damon.springsecuritytool.dto.auth.Violation;

import java.util.List;

/**
 * @author damon 20250521
 */
@Getter
public class ValidationException extends RuntimeException {
    private final transient List<Violation> violations;
    private final Type type;

    public ValidationException(List<Violation> violations, Type type) {
        this.violations = violations;
        this.type = type;
    }

    public enum Type {
        INBOUND_REQUEST,
        OUTBOUND_RESPONSE;

        Type() {
        }
    }
}
