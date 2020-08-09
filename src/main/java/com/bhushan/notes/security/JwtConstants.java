package com.bhushan.notes.security;

public class JwtConstants {
    public static final String AUTH_LOGIN_URL = "/authenticate";
    public static final String JWT_SECRET = "Zq4t7w!z%C*F-JaNcRfUjXn2r5u8x/A?D(G+KbPeSgVkYp3s6v9y$B&E)H@McQfT";

    // JWT token defaults
    public static final String TOKEN_PREFIX = "Bearer";
    public static final String TOKEN_TYPE = "JWT";
    public static final String TOKEN_ISSUER = "notes-app";
    public static final String TOKEN_AUDIENCE = "secure-app";
    public static final String TOKEN_COOKIE = "auth-token";

    private JwtConstants() {
        throw new IllegalStateException("Cannot create instance of static util class");
    }
}
