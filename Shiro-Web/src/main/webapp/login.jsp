<%--
  Created by IntelliJ IDEA.
  User: guoxi
  Date: 2019/1/13
  Time: 14:48
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page isELIgnored="false" %>
<html>
<head>
    <title>登录</title>
</head>
<body>
<form action="/login" method="post">
    用户名：<input type="text" id="username" name="username"><br/>
    密  码：<input type="password" id="password" name="password"><br/>
    <input type="submit" value="登录"><br/>

</form>
<h4 class="text-center" style="color:red">${error}</h4>
</body>
</html>
