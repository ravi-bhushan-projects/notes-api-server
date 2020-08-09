package com.bhushan.notes.Bootstrap;

import com.bhushan.notes.domain.Role;
import com.bhushan.notes.domain.User;
import com.bhushan.notes.repository.RoleRepository;
import com.bhushan.notes.repository.UserRepository;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class DevBootstrap implements ApplicationListener<ContextRefreshedEvent> {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    public DevBootstrap(UserRepository userRepository, RoleRepository roleRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        addRoles();
        addUsers();
    }

    private void addRoles() {
        Role role = new Role();
        role.setName("ADMIN");
        role.setName("SUPER_ADMIN");
        this.roleRepository.save(role);
    }

    private void addUsers() {
        User user = new User();
        user.setUsername("user");
        user.setPassword(passwordEncoder.encode("password"));
        List<Role> roles = this.roleRepository.findAll();
        user.setRoles(roles.stream().collect(Collectors.toSet()));
        userRepository.save(user);
    }
}
