package com.bigbilii.realm;

import com.bigbilii.entity.Permission;
import com.bigbilii.entity.Role;
import com.bigbilii.entity.User;
import com.bigbilii.service.UserService;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

import javax.annotation.Resource;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class UserRealm extends AuthorizingRealm {

    @Resource
    UserService userService;


    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("权限校验");
        String username = (String) principalCollection.getPrimaryPrincipal();

        SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
        Set<String> role = new HashSet<String>();
        /*获取角色信息*/
        List<Role> roles = userService.findRoles(username);
        for (Role r : roles) {
            role.add(r.getname());
        }
        System.out.println("!!!!!!!!!!! 添加role" + role);
        authorizationInfo.setRoles(role);
        /*获取权限信息*/
        List<Permission> permissions = userService.findPermissions(username);
        Set<String> permission = new HashSet<String>();
        for (Permission p : permissions) {
            permission.add(p.getname());
        }
        System.out.println("!!!!!!!!!!! 添加permission" + permission);
        authorizationInfo.setStringPermissions(permission);

        /*返回角色和权限信息，交给AuthenticationRealm进行角色权限匹配*/
        return authorizationInfo;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("权限校验");
        String username = (String) authenticationToken.getPrincipal();

        /*获取用户信息*/
        User user = userService.findByName(username);

        if (user == null) {
            throw new UnknownAccountException();
        }

        /*返回认证信息，交给AuthenticationRealm进行密码匹配*/
        SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(
                user.getUsername(),
                user.getPassword(),
                ByteSource.Util.bytes(user.getCredentialsSalt()),
                getName()
        );
        return authenticationInfo;
    }
}
