---
title: Shiro-ssm项目集成与实现
date: 2019-01-16 12:07:03
tags:
    - Shiro
    - Spring
    - RBAC
categories:
    - Shiro
---

## 前言

学习技术，最重要的是实践。

本着上面的原则，学习玩shiro基本知识之后，我也动手写了一个小demo，来熟悉下shiro。

在这个小项目中，需求是实现`普通用户`和`管理员`的权限分离，管理员可以对普通用户进行`CRUD`，普通用户只能登录。

这个项目中，涉及到以下技术点:

- SSM（Spring\SpringMVC\Mybatis）
- Shiro的授权和角色认证
- Shiro自定义Realm
- Shiro加密
- RBAC数据库设计
- RESTFul api设计

## RBAC数据库设计

来自wiki的解释：

> 以角色为基础的访问控制（英语：Role-based access control，RBAC），是资讯安全领域中，一种较新且广为使用的访问控制机制，其不同于强制访问控制以及自由选定访问控制直接赋予使用者权限，而是将权限赋予角色.

之所以采用RBAC设计模式来进行权限管理的数据库设计，是因为我们可以避免让`主体`直接与`权限`关联，而通过`角色`来进行连接，它通过`主体-角色-权限`这三张表，来实现主体与角色，角色与权限的关系。

所以我创建了以下五张表：
- user：用户表
- role：角色表
- promission：权限表
- user_role：用户角色关系表
- role_promission：角色权限关系表

### 源码
```
create table user
(
  id       int auto_increment
    primary key,
  username varchar(100) null comment '用户名',
  password varchar(100) null comment '密码',
  salt     varchar(100) null,
  constraint user_username_uindex
    unique (username)
)
  comment '用户表';

create table role
(
  id          int auto_increment
    primary key,
  name        varchar(20) null comment '权限名称',
  description varchar(50) null comment '权限描述'
)
  comment '角色表';

create table permission
(
  id          int auto_increment
    primary key,
  name        varchar(20) null comment '权限名称',
  description varchar(50) null comment '权限描述表'
)
  comment '权限表';

create table user_role
(
  user_id int null,
  role_id int null,
  constraint user_role_rid_fk
    foreign key (role_id) references role (id),
  constraint user_role_uid_fk
    foreign key (user_id) references user (id)
)
  comment '用户角色表';

create table role_premission
(
  role_id       int null,
  permission_id int null,
  constraint role_premission_pid_fk
    foreign key (permission_id) references permission (id),
  constraint role_premission_uid_fk
    foreign key (role_id) references role (id)
);
```
## Shiro遇到Spring

在SSM架构中，通过XMl文件的方式来设置相关配置信息。由于是学习Shiro，所以其他的Spring相关的配置就不具体展示。

### Web.xml

在`web.xml`中配置shiro拦截器，以拦截所有的请求，通过shiro来进行权限管理。
注意：下面我添加了加载spring配置文件的配置信息，注意配置文件的命名格式需要为`spring-*.xml`
```
<!-- shiro 安全过滤器 -->
    <filter>
        <filter-name>shiroFilter</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
        <async-supported>true</async-supported>
        <init-param>
            <param-name>targetFilterLifecycle</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>shiroFilter</filter-name>
        <url-pattern>/*</url-pattern>
    </filter-mapping>

<!--加载spring配置文件-->
    <context-param>
        <param-name>contextConfigLocation</param-name>
        <param-value>classpath:spring/spring-*.xml</param-value>
    </context-param>
    <listener>
        <listener-class>org.springframework.web.context.ContextLoaderListener</listener-class>
    </listener>
```
### spring-shiro.xml

在spring-shiro.xml中，配置了shiro所有在spring中需要配置的相关信息，下面来具体看一下。

```
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans"
       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:util="http://www.springframework.org/schema/util"
       xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd http://www.springframework.org/schema/util http://www.springframework.org/schema/util/spring-util.xsd">


    <!--Web拦截器-->
    <bean id="shiroFilter" class="org.apache.shiro.spring.web.ShiroFilterFactoryBean">
        <!--安全认证管理器-->
        <property name="securityManager" ref="securityManager"/>
        <!--登录页面-->
        <property name="loginUrl" value="/login.jsp"/>
        <!-- 自定义的过滤器链，从上向下执行，一般将`/**`放到最下面 -->
        <property name="filterChainDefinitions">
            <value>
                <!--静态资源-->
                /static/** = anon
                /lib/** = anon
                /js/** = anon

                <!--登录页面与请求-->
                /login.jsp = anon
                /login = anon
                <!--登出-->
                /logout = logout
                <!--登录后可访问主页-->
                /index.jsp = user
                <!--所有请求-->
                /** = user
            </value>
        </property>

    </bean>

    <!--Shiro安全管理器-->
    <bean id="securityManager" class="org.apache.shiro.web.mgt.DefaultWebSecurityManager">
        <property name="realm" ref="userRealm"/>
    </bean>

    <!--自定义Realm-->
    <bean id="userRealm" class="com.bigbilii.realm.UserRealm">
        <!-- 使用credentialsMatcher实现密码验证服务 -->
        <property name="credentialsMatcher" ref="credentialsMatcher"/>
    </bean>

    <!--密码匹配过程-->
    <bean id="credentialsMatcher" class="org.apache.shiro.authc.credential.HashedCredentialsMatcher  ">
        <!--加密算法名称-->
        <property name="hashAlgorithmName" value="md5"/>
        <!--加盐次数-->
        <property name="hashIterations" value="2"/>
        <!--是否存储散列后的密码为16进制-->
        <property name="storedCredentialsHexEncoded" value="true"/>
    </bean>

    <!-- Shiro生命周期处理器-->
    <bean id="lifecycleBeanPostProcessor" class="org.apache.shiro.spring.LifecycleBeanPostProcessor"/>
</beans>
```

在配置完这些之后，shiro的spring配置文件也基本告一段落，在上面的配置信息中，有两个值得注意的地方。
一个是`filterChainDefinitions`自定义拦截链，这个是从上往下执行的，也就是执行第一次匹配成功的结果，下面是部分默认拦截器的说明：
|拦截器名|说明|
|---|---- |
|authc|基于表单的拦截器，其拦截的请求必须是通过登录验证的|
|logout|退出拦截器，主要属性：redirectUrl：退出成功后重定向的地址（/）;示例“/logout=logout”|
|user|用户拦截器，用户已经身份验证/记住我登录的都可；示例“/**=user”|
|anon|匿名拦截器，即不需要登录即可访问；一般用于静态资源过滤；示例“/static/**=anon”|

另外一个是`userRealm`自定义realm。

## 自定义Realm

Shiro的`SecurityManager`从`Realm`中获取安全数据，而Shiro自带了一些Realm可以是我们能够提供安全数据给Shiro做认证，但当数据较为复杂，自带的Realm功能就不能满足业务需求，这时就需要自定义Realm。

下面的`UserRealm`要实现授权和认证两个功能，所以继承了`AuthorizingRealm`类，因为它继承了`AuthenticatingRealm`类，所以可以同时实现授权和认证两个功能，需要对`doGetAuthorizationInfo()`和`doGetAuthenticationInfo()`方法进行重写。下面是源码：
```
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
        for (Role r : roles){
            role.add(r.getname());
        }
        System.out.println("!!!!!!!!!!! 添加role" + role);
        authorizationInfo.setRoles(role);
        /*获取权限信息*/
        List<Permission> permissions = userService.findPermissions(username);
        Set<String> permission = new HashSet<String>();
        for (Permission p : permissions){
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
```

大部分流程都是用注解标注了。下面来看一下具体UserRealm是如何工作的。

### 登录认证

```
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
            return Result.message(200,"登录成功");
        } else {
            return Result.message(401,"用户名或密码错误");
        }
    }
}
```
具体流程：
1. 从请求中回去了提交的`username`和`password`，将获取到的用户名和密码设置成Token。然后回去主体`Subject`，因为在Spring的配置文件中已经初始化`SecurityManager`和设置了`UserRealm`，所以可以直接获取主体。
2. 调用`login()`方法，然后`SecurityManager`会委派`Authenticator`调用自定义Realm的认证方法，也就是我们重写的` doGetAuthenticationInfo()`方法，其中的`authenticationToken`参数也就是我们之前封装的token。
3. 进入到我们的方法后，我们通过service服务层去获取数据库的信息，获取到数据库的账号密码，注意：数据库的密码是加密处理的，所以取到密码和前台传入的明文密码不能匹配。
4. 获取到数据库信息之后，将信息封装到`SimpleAuthenticationInfo`实例，返回给`Authenticator`做密码认证，因为在配置文件中，设置了`credentialsMatcher`密码认证过程，所以`Authenticator`也会去调用这个密码认证过程，将token中储存的明文密码进行加密，与数据库的加密密码进行匹配，从而认证。

### 加密

在上面的登录验证过程中，多次提到了密码加密问题，这个问题也是非常常见的，在实际项目中，不可能使用明文密码进行存储，都会用到加密技术，而Shiro也支持加密。

具体的加密技术不是本文的重点，所以不会过多介绍。下面是我封装的一个加密工具，用于为用户进行加密处理。

```
@Component
public class PasswordHelper {
    private RandomNumberGenerator randomNumberGenerator = new SecureRandomNumberGenerator();

    private String algorithName = "MD5";
    private int hashInterations = 2;

    //加密算法
    public void encryptPassword(User user){
        if (user.getPassword() != null){
            //对user对象设置盐：salt；这个盐值是randomNumberGenerator生成的随机数
            user.setSalt(randomNumberGenerator.nextBytes().toHex());

            //调用SimpleHash指定散列算法参数：1、算法名称；2、用户输入的密码；3、盐值（随机生成的）；4、迭代次数
            String newPassword = new SimpleHash(
                    algorithName,
                    user.getPassword(),
                    ByteSource.Util.bytes(user.getCredentialsSalt()),
                    hashInterations).toHex();
            user.setPassword(newPassword);
        }
    }
}
```
具体流程：
1. 通过`RandomNumberGenerator`随机生成盐值，并设置成用户的盐值
2. 通过`SimpleHash`实例来构造一个加密密码，参数中，第三个盐值是【用户名+随机盐值】
3. 设置用户的加密密码

值得注意的是：`algorithName`和`hashInterations`是需要提前约定的，这样生成用户的密码的加密方式和Shiro配置的`credentialsMatcher`密码认证过程的加密方式才能一致。

### 授权

首先，在用户表中添加两个用户，一个当管理员，一个当普通用户.

然后在数据库插入几条授权需要用到的信息，sql如下

```
insert into permission values(1,'resource:create','用户新增' );
insert into permission values(2,'user:update','用户修改' );
insert into permission values(3,'user:delete','用户删除' );
insert into permission values(4,'user:view', '用户查看' );
insert into permission values(5,'role:update', '角色更新');
insert into permission values(6,'role:delete', '角色删除');
insert into permission values(7,'role:create', '角色创建');
insert into permission values(8,'role:view', '角色查看');
insert into permission values(9,'news:view', '新闻查看');

insert into role values(1,'admin','管理员');
insert into role values(2,'user','普通用户');

insert into role_premission values(1,1);
insert into role_premission values(1,2);
insert into role_premission values(1,3);
insert into role_premission values(1,4);
insert into role_premission values(1,5);
insert into role_premission values(1,6);
insert into role_premission values(1,7);
insert into role_premission values(1,8);
insert into role_premission values(1,9);
insert into role_premission values(2,9);

insert into user_role values(1,1);
insert into user_role values(2,2);
```

然后来看下我们的UserController，这里采用的是RESTFul设计
```
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
        return Result.message(200, "查询用户成功").add("users",users);
    }
}
```
通过`@RequiresPermissions()`这个注解来控制权限登录，除了这个注解，还有其他的授权控制注解。
| | |
|-|-|
|@RequiresAuthentication|表示当前Subject已经通过login身份验证；即Subject.isAuthenticated() == true；否则就拦截|
|@RequiresUser|表示当前Subject已经通过login身份验证或通过记住我登录；否则就拦截|
|@RequiresGuest|表示当前Subject没有身份验证或通过记住我登录过，即是游客身份|
|@RequiresRoles(admin)|表示当前Subject需要admin角色|
|@RequiresPermissions("user:insert")|表示当前Subject需要拥有"user:insert"权限|

值得注意的是：某些shiro注解需要AOP功能进行判断,所以在springmvc配置文件中开启shiro spring AOP的支持
```
 <aop:config proxy-target-class="true"/>
    <bean class="org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor">
        <property name="securityManager" ref="securityManager"/>
    </bean>
```
然后回过头来看下我们的`UserReaml`的`doGetAuthorizationInfo`方法。

在该方法中，通过service获取到role信息和premission信息，其实可以不用回去role信息的，因为我们在controller层是通过premission来控制权限的。

**问题**

在这里的时候，我发现了一个问题：我在设计controller时，通过premisson来控制，所以需要在数据库获取permission，但在我们之前的表设计，通过用户名来获取到permission，需要5张表连接，故在这里可以自行进行优化。

## 关于RESTFul

RESTFul是一种接口开发设计规范，是Representational State Transfer的缩写，其意为“表现层状态转化”，省略了主语。"表现层"其实指的是"资源"（Resources）的"表现层"。REST认为，每一个URL都是一种资源，所有的操作都是对资源的操作，而不同的操作主要使用HTTP动词来表示。
|方法|	含义|
|-|-|
|GET（SELECT）|	从服务器取出资源（一项或多项）|
|POST（CREATE）	|在服务器新建一个资源|
|PUT（UPDATE）|	在服务器更新资源（客户端提供改变后的完整资源）|
|DELETE（DELETE）	|从服务器删除资源|
|HEAD	|获取资源的元数据|
|OPTIONS	|获取信息，关于资源的哪些属性是客户端可以改变的|


## 总结

这次通过Shiro配合SSM框架写了个小demo，但可以看到有个明显的性能问题：每次到需要处理权限问题的请求的时候，都需要去数据库里获取相应的信息，这对性能的消耗很大，所以在之后会加入缓存的处理。由于我现在对缓存的运用不是很熟悉，在之后的学习中，会对这里的进行升级。

源码：https://github.com/bigbilii/Shiro
