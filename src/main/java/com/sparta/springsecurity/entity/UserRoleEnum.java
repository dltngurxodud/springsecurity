package com.sparta.springsecurity.entity;

public enum UserRoleEnum {
    USER(Authority.USER),  // 사용자 권한
    ADMIN(Authority.ADMIN);  // 관리자 권한

    private final String authority; // String으로 권한을 비교하기 위해서 사용하였다.

    UserRoleEnum(String authority) { // String으로 변환해서 비교하기 위해서 User와 ADMIN을 나누기 위한 비교
        this.authority = authority;
    }

    public String getAuthority() {
        return this.authority;
    }

    public static class Authority {
        public static final String USER = "ROLE_USER";
        public static final String ADMIN = "ROLE_ADMIN";






    }

}