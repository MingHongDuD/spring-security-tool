package org.damon.springsecuritytool.util;

import java.util.regex.Pattern;

/**
 * @author damon 20250521
 */
public class JwtUtils {
    private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.?[A-Za-z0-9-_.+/=]*$");

    private JwtUtils() {
    }

    public static boolean isJwtFormat(String jwtId) {
        return JWT_PATTERN.matcher(jwtId).matches();
    }

}
