package com.bhushan.notes.controller.v1;

import com.bhushan.notes.dto.UserDTO;
import com.bhushan.notes.dto.UserDetailsDTO;
import com.bhushan.notes.mapper.UserMapper;
import com.bhushan.notes.security.JwtConstants;
import com.bhushan.notes.service.UserService;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/user")
public class UserController {

    private final UserService userService;
    private final UserMapper userMapper;

    public UserController(UserService userService, UserMapper userMapper) {
        this.userService = userService;
        this.userMapper = userMapper;
    }

    @PostMapping
    public void registerUser(@RequestBody UserDTO userDTO) {
        this.userService.registerUser(userDTO);
    }

    @GetMapping
    public UserDetailsDTO fetchUserDetails() {
        var principal = SecurityContextHolder.getContext().getAuthentication();
        UserDetailsDTO userDetailsDTO = new UserDetailsDTO();
        userDetailsDTO.setUsername(principal.getPrincipal().toString());
        userDetailsDTO.setRoles(principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet()));
        return userDetailsDTO;
    }

    @GetMapping("/logout")
    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) {
        Cookie cookie = new Cookie(JwtConstants.TOKEN_COOKIE, null);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true);
        httpServletResponse.addCookie(cookie);
    }
}
