package com.bhushan.notes.mapper;

import com.bhushan.notes.domain.User;
import com.bhushan.notes.dto.UserDTO;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    User toUser(UserDTO userDTO);
    UserDTO toUserDTO(User user);
}
