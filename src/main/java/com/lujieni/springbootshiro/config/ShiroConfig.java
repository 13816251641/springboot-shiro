package com.lujieni.springbootshiro.config;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.pam.AllSuccessfulStrategy;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.authc.pam.FirstSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class ShiroConfig {
    /**
     * 创建ShiroFilterFactoryBean
     */
    @Bean
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(DefaultWebSecurityManager defaultWebSecurityManager){
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        //添加shiro内置过滤器
        shiroFilterFactoryBean.setSecurityManager(defaultWebSecurityManager);
        /*
           shiro内置过滤器:可以实现权限相关的拦截器
                常用的过滤器
                    anon:无需认证(登录)即可访问
                    authc:必须认证才可以访问
                    user:如果使用rememberMe的功能可以直接访问
                    perms:该资源必须得到资源权限才可以访问
                    role:该资源必须得到角色权限才可以访问
                    来自dev的问候
                    master自己加的
         */
        Map<String,String> filterMap = new LinkedHashMap<>();
        //filterMap.put("/add","authc");
        //filterMap.put("/update","authc");
        filterMap.put("/add","perms[user:add]");
        filterMap.put("/update","perms[user:update]");
        filterMap.put("/testThymeleaf","anon");
        filterMap.put("/login","anon");
        filterMap.put("/toLogin","anon");
        //主要这行代码必须放在所有权限设置的最后，不然会导致所有 url 都被拦截
        filterMap.put("/**", "authc");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterMap);
        //修改登录界面的地址
        shiroFilterFactoryBean.setLoginUrl("/toLogin");
        //修改没有授权地址
        shiroFilterFactoryBean.setUnauthorizedUrl("/noAuth");
        return shiroFilterFactoryBean;
    }


    /**
     * 创建DefaultWebSecurityManager
     */
    @Bean
    public DefaultWebSecurityManager getDefaultWebSecurityManager(UserRealm userRealm,SecondRealm secondRealm){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        ModularRealmAuthenticator modularRealmAuthenticator = new ModularRealmAuthenticator();
        modularRealmAuthenticator.setAuthenticationStrategy(new AtLeastOneSuccessfulStrategy());
        securityManager.setAuthenticator(modularRealmAuthenticator);
        /* 关联单relam */
        //securityManager.setRealm(userRealm);
        List<Realm> list = new ArrayList<>();
        list.add(userRealm);
        list.add(secondRealm);
        securityManager.setRealms(list);
        return securityManager;
    }

    /**
     * 创建Realm
     */
    @Bean
    public UserRealm getUserRealm(HashedCredentialsMatcher hashedCredentialsMatcher){
        UserRealm userRealm = new UserRealm();
        userRealm.setAuthorizationCachingEnabled(false);
        userRealm.setCredentialsMatcher(hashedCredentialsMatcher);
        return userRealm;
    }

    /**
     * 创建Realm
     */
    @Bean
    public SecondRealm getSecondRealm(HashedCredentialsMatcher hashedCredentialsMatcher){
        SecondRealm secondRealm = new SecondRealm();
        secondRealm.setAuthorizationCachingEnabled(false);
        secondRealm.setCredentialsMatcher(hashedCredentialsMatcher);
        return secondRealm;
    }


    /**
     * 密码校验规则HashedCredentialsMatcher
     * 这个类是为了对密码进行编码的 ,
     * 防止密码在数据库里明码保存 , 当然在登陆认证的时候 ,
     * 这个类也负责对form里输入的密码进行编码
     * 处理认证匹配处理器：如果自定义需要实现继承HashedCredentialsMatcher
     */
    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher credentialsMatcher = new HashedCredentialsMatcher();
        //指定加密方式为MD5
        credentialsMatcher.setHashAlgorithmName("MD5");
        //加密次数
        credentialsMatcher.setHashIterations(1024);
        //是否存储为16进制
        credentialsMatcher.setStoredCredentialsHexEncoded(true);
        return credentialsMatcher;
    }

}
