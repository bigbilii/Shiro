package com.bigbilii.mapper;

import com.bigbilii.entity.Permission;
import com.bigbilii.entity.Role;
import com.bigbilii.entity.User;

import java.util.List;

public interface UserMapper {

    User findByName(String username);

    void insert(User user);

    void delete(String username);

    List<User> query();

    List<Role> findRoles(String username);

    List<Permission> findPermissions(String username);
}
