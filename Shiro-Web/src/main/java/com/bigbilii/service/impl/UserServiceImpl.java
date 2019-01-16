package com.bigbilii.service.impl;

import com.bigbilii.entity.Permission;
import com.bigbilii.entity.Role;
import com.bigbilii.entity.User;
import com.bigbilii.mapper.UserMapper;
import com.bigbilii.service.UserService;
import com.bigbilii.utils.PasswordHelper;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.List;

@Service
public class UserServiceImpl implements UserService {

    @Resource
    private UserMapper userMapper;

    @Resource
    private PasswordHelper passwordHelper;


    @Override
    public User findByName(String username) {
        return userMapper.findByName(username);
    }

    @Override
    public void insert(User user) {
        passwordHelper.encryptPassword(user);
        userMapper.insert(user);
    }

    @Override
    public void delete(String username) {
        userMapper.delete(username);
    }

    @Override
    public List<User> query() {
        return userMapper.query();
    }

    @Override
    public List<Role> findRoles(String username) {
        return userMapper.findRoles(username);
    }

    @Override
    public List<Permission> findPermissions(String username) {
        return userMapper.findPermissions(username);
    }
}
