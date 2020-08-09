package com.bhushan.notes.dto;

import java.util.Set;

public class UserDetailsDTO {
    private String username;
    private Set<String> roles;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    @Override
    public String toString() {
        return "UserDetailsDTO{" +
                "username='" + username + '\'' +
                ", roles=" + roles +
                '}';
    }
}
