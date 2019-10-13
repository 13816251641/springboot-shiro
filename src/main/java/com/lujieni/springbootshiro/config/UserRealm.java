package com.lujieni.springbootshiro.config;

import com.lujieni.springbootshiro.entity.User;
import com.lujieni.springbootshiro.mapper.UserMapper;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.springframework.beans.factory.annotation.Autowired;


/**
 * 自定义Realm程序
 */
public class UserRealm extends AuthorizingRealm {

    @Autowired
    private UserMapper userMapper;

    /**
     * 执行授权逻辑
     * @param principals
     * @return
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
        System.out.println("执行授权逻辑");
        //给资源进行授权
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        //添加资源的授权字符串
        //info.addStringPermission("user:add");

        //到数据库查询当前登录用户的授权字符串
        //获取当前登录用户
        Subject subject = SecurityUtils.getSubject();
        User user = (User)subject.getPrincipal();
        info.addStringPermission(user.getPerms());
        return info;
    }

    /**
     * 执行认证逻辑
     * @param arg
     * @return
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken arg) throws AuthenticationException {
        System.out.println("执行认证逻辑");
        //编写shiro判断逻辑,判断用户名和密码
        //1.判断用户名
        UsernamePasswordToken token = (UsernamePasswordToken)arg;
        User user = userMapper.findUserByUsername(token.getUsername());
        if(null == user) {
            /* 用户名不存在抛出UnknownAccountExcepetion */
            throw new UnknownAccountException();
        }
        /*
            利用SimpleAuthenticationInfo可以实现让shiro自动帮我们判断密码
            第一个参数可以放置用户对象信息,同时可以通过securityutis.getsubject().getprincipal();取出
            第二个参数是在数据库中这个用户的真实密码,交给SimpleAuthenticationInfo来和用户输入的作比较
         */
        /* 盐值,登录时用户输入的用户名 */
        ByteSource credentialsSalt = ByteSource.Util.bytes(token.getUsername());
        /*
           MD5加密是可不逆的,所以这里的比较是将用户前端输入的密码进行MD5加密并加盐之后
           和数据库中存储的进行比较
         */
        return new SimpleAuthenticationInfo(user,user.getPassword(),credentialsSalt,"");
    }
}
