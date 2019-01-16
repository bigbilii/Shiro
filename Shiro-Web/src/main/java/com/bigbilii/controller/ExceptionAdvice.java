package com.bigbilii.controller;

import com.bigbilii.entity.Result;
import com.bigbilii.realm.UserRealm;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authz.UnauthorizedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionAdvice {

    private static final Logger LOGGER = LogManager.getLogger(UserRealm.class);

    /**
     * 信息无法读取
     *
     * @param e
     * @return
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Result handleHttpMessageNotReadableException(Exception e) {
        e.printStackTrace();
        return Result.message(400, "无法读取");
    }

    /**
     * 处理参数异常
     *
     * @param e
     * @return
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public Result handleMethodArgumentNotValidException(Exception e) {
        return Result.message(400, "参数验证失败");
    }


    /**
     * 数学计算错误
     *
     * @param e
     * @return
     */
    @ExceptionHandler(ArithmeticException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public Result handleArithmeticException(ArithmeticException e) {
        return Result.message(500, "服务器内部错误");
    }

    /**
     * 登陆错误
     *
     * @param e
     * @return
     */
    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Result handleAuthenticationException(AuthenticationException e) {
        LOGGER.error(e);
        return Result.message(401, "登陆错误");
    }

    @ExceptionHandler(IncorrectCredentialsException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Result handleIncorrectCredentialsException(AuthenticationException e) {
        return Result.message(401, "用户名或密码错误");
    }

    @ExceptionHandler(UnknownAccountException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public Result handleUnknownAccountException(UnknownAccountException e) {
        LOGGER.error(e);
        return Result.message(401, "请登录");
    }


    /**
     * 没有权限——shiro
     *
     * @param e
     * @return
     */
    @ExceptionHandler(UnauthorizedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public Result handleUnauthorizedException(UnauthorizedException e) {
        return Result.message(403, "没有权限");
    }
}
