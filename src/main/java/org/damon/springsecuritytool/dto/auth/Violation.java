package org.damon.springsecuritytool.dto.auth;

import lombok.Data;
import lombok.ToString;

/**
 * @author damon 20250521
 */
@ToString
@Data
public class Violation {
    /*
     * code
     */
    private String code;
    /*
     * message
     */
    private String message;
    /*
     * param
     */
    private String param;
    /*
     * type
     */
    private Type type;

    public Violation(String code, String message) {
        this.code = code;
        this.message = message;
        this.type = Violation.Type.ERROR_DETAILS;
    }

    public Violation(String code, String message, String param) {
        this.code = code;
        this.message = message;
        this.param = param;
        this.type = Violation.Type.ERROR_DETAILS;
    }

    public Violation(String code, String message, Type type) {
        this.code = code;
        this.message = message;
        this.type = type;
    }

    public Violation(String code, String message, String param, Type type) {
        this.code = code;
        this.message = message;
        this.param = param;
        this.type = type;
    }

    public enum Type {
        ERROR,
        ERROR_DETAILS;

        Type() {
        }
    }
}
