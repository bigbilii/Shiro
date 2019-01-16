package com.bigbilii.controller;

import com.bigbilii.entity.Result;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.subject.Subject;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/login")
public class LoginController {


    /**
     * 登录验证
     *
     * @param username 用户名
     * @param password 密码
     * @return
     */
    @PostMapping
    public Result login(@RequestParam(value = "username", required = false) String username,
                        @RequestParam(value = "password", required = false) String password) {
        System.out.println("账号:" + username + ",密码:" + password);
        if (username != null && password != null) {
            Subject subject = SecurityUtils.getSubject();
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);

            subject.login(token);
            return Result.message(200, "登录成功");
        } else {
            return Result.message(401, "用户名或密码错误");
        }
    }
}
