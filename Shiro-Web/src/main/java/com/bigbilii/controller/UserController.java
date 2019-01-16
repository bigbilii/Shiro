package com.bigbilii.controller;

import com.bigbilii.entity.Result;
import com.bigbilii.entity.User;
import com.bigbilii.service.UserService;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

    @Resource
    private UserService userService;

    @RequiresPermissions("user:insert")
    @PostMapping
    public Result insert(@RequestBody User user) {

        System.out.println(user);
        userService.insert(user);
        return Result.message(200, "创建用户成功");

    }

    @RequiresPermissions("user:delete")
    @DeleteMapping
    public Result delete(String username) {
        System.out.println("删除");

        userService.delete(username);
        return Result.message(200, "删除用户成功");
    }

    @RequiresPermissions("user:view")
    @GetMapping
    public Result query() {
        System.out.println("查询");

        List<User> users = userService.query();
        return Result.message(200, "查询用户成功").add("users", users);
    }
}
