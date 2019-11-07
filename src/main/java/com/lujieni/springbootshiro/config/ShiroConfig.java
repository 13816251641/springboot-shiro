package com.lujieni.springbootshiro.config;

import com.lujieni.springbootshiro.entity.SysPermissionInit;
import com.lujieni.springbootshiro.mapper.SysPermissionInitMapper;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.authc.pam.AllSuccessfulStrategy;
import org.apache.shiro.authc.pam.AtLeastOneSuccessfulStrategy;
import org.apache.shiro.authc.pam.FirstSuccessfulStrategy;
import org.apache.shiro.authc.pam.ModularRealmAuthenticator;
import org.apache.shiro.realm.Realm;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class ShiroConfig {
    @Autowired
    private SysPermissionInitMapper sysPermissionInitMapper;

    @Value("${spring.redis.hostName}")
    private String redisHostName;

    @Value("${spring.redis.password}")
    private String redisPassword;

    @Value("${spring.redis.timeout}")
    private int redisTimeout;//从application.properties中读取


    /**
     * 配置shiro redisManager,大家公用的
     *
     * @return
     */
    @Bean
    public RedisManager redisManager() {
        RedisManager redisManager = new RedisManager();
        redisManager.setHost(redisHostName);
        redisManager.setPassword(redisPassword);
        /*配置连接超时时间*/
        redisManager.setTimeout(redisTimeout);
        return redisManager;
    }

    /**
     * cacheManager 缓存 redis实现 这个cacheManager的功能我很闷逼
     *
     * @return
     */
    @Bean
    public RedisCacheManager cacheManager() {
        RedisCacheManager redisCacheManager = new RedisCacheManager();
        redisCacheManager.setRedisManager(redisManager());//会使用bean
        redisCacheManager.setKeyPrefix("cacheManager:");
        return redisCacheManager;
    }

    /**
     * RedisSessionDAO shiro sessionDao层的实现 通过redis
     * 发现实际在redis中命名空间用的是这个
     */
    @Bean
    public RedisSessionDAO redisSessionDAO() {
        RedisSessionDAO redisSessionDAO = new RedisSessionDAO();
        redisSessionDAO.setRedisManager(redisManager());
        redisSessionDAO.setKeyPrefix("redisSessionDAO:");
        return redisSessionDAO;
    }

    /**
     * shiro session的管理
     * SessionManager注入sessionDAO，实现Session的CRUD
     */
    @Bean
    public DefaultWebSessionManager sessionManager() {
        DefaultWebSessionManager sessionManager = new DefaultWebSessionManager();
        sessionManager.setSessionDAO(redisSessionDAO());
        return sessionManager;
    }

    /**
     * 创建DefaultWebSecurityManager
     */
    @Bean
    public DefaultWebSecurityManager getDefaultWebSecurityManager(ThirdRealm thirdRealm,SecondRealm secondRealm,UserRealm userRealm){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        /* 设置多realm下的认证策略 */
        ModularRealmAuthenticator modularRealmAuthenticator = new ModularRealmAuthenticator();
        modularRealmAuthenticator.setAuthenticationStrategy(new AtLeastOneSuccessfulStrategy());
        securityManager.setAuthenticator(modularRealmAuthenticator);
        /* 关联单realm */
        //securityManager.setRealm(userRealm);
        List<Realm> list = new ArrayList<>();
        list.add(userRealm);
        list.add(secondRealm);
        list.add(thirdRealm);
        securityManager.setRealms(list);

        /*自定义session管理 使用redis */
        securityManager.setSessionManager(sessionManager());
        /*
           自定义缓存实现,使用redis,当配置了该cacheManager且对应realm的
           setAuthorizationCachingEnabled为true时可以缓存授权对应realm
           的授权信息放入redis中,效果是对应realm的doGetAuthorizationInfo
           的代码并不是每次都会执行了,只会第一次执行
        */
        securityManager.setCacheManager(cacheManager());
        return securityManager;
    }



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
       /*
           代码中配置权限,因为add,update设置了roles权限,所以无需authc,默认就是需要authc
           filterMap.put("/add","roles[jeecg]");
           filterMap.put("/update","roles[admin]");
           filterMap.put("/delete","perms[user:delete]");
           filterMap.put("/testThymeleaf","anon");
           filterMap.put("/login","anon");
           主要这行代码必须放在所有权限设置的最后,不然会导致所有url都被拦截
           filterMap.put("/**", "authc");
       */

        List<SysPermissionInit> list = sysPermissionInitMapper.getAll();
        list.forEach(e->filterMap.put(e.getUrl(),e.getPermissionInit()));

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterMap);
        /*
           如果不设置默认会自动寻找Web工程根目录下的"/login.jsp"页面,
           这个url即使不配置anon也可以被外部访问到
         */
        shiroFilterFactoryBean.setLoginUrl("/toLogin");
        //修改没有授权地址
        shiroFilterFactoryBean.setUnauthorizedUrl("/noAuth");
        return shiroFilterFactoryBean;
    }


    /**
     * 使shiro支持注解
     * @param defaultWebSecurityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager defaultWebSecurityManager) {
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor =new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(defaultWebSecurityManager);
        return authorizationAttributeSourceAdvisor;
    }

    /**
     * 使shiro支持注解
     * @return
     */
    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator app = new DefaultAdvisorAutoProxyCreator();
        app.setProxyTargetClass(true);
        return app;
    }


    /**
     * 创建Realm
     */
    @Bean
    public UserRealm getUserRealm(HashedCredentialsMatcher hashedCredentialsMatcher){
        UserRealm userRealm = new UserRealm();
        /*
          启用授权缓存，即缓存AuthorizationInfo信息，默认false,
          当设置为true且配置了setCacheManager后即可缓存授权逻辑,
          将信息存入redis中,效果是不用每次都执行doGetAuthorizationInfo
          方法,只会第一次执行
        */
        userRealm.setAuthorizationCachingEnabled(true);
        userRealm.setCredentialsMatcher(hashedCredentialsMatcher);
        return userRealm;
    }

    /**
     * 创建Realm
     */
    @Bean
    public SecondRealm getSecondRealm(HashedCredentialsMatcher hashedCredentialsMatcher){
        SecondRealm secondRealm = new SecondRealm();
        /*
          启用授权缓存，即缓存AuthorizationInfo信息，默认false,
          当设置为true且配置了setCacheManager后即可缓存授权逻辑,
          将信息存入redis中,效果是不用每次都执行doGetAuthorizationInfo
          方法,只会第一次执行
        */
        secondRealm.setAuthorizationCachingEnabled(true);
        /*设置密码比较器*/
        secondRealm.setCredentialsMatcher(hashedCredentialsMatcher);
        return secondRealm;
    }

    /**
     * 创建Realm
     */
    @Bean
    public ThirdRealm getThirdRealm(HashedCredentialsMatcher hashedCredentialsMatcher){
        ThirdRealm thirdRealm = new ThirdRealm();
        /*
          启用授权缓存，即缓存AuthorizationInfo信息，默认false,
          当设置为true且配置了setCacheManager后即可缓存授权逻辑,
          将信息存入redis中,效果是不用每次都执行doGetAuthorizationInfo
          方法,只会第一次执行
        */
        thirdRealm.setAuthorizationCachingEnabled(true);
        /*设置密码比较器*/
        thirdRealm.setCredentialsMatcher(hashedCredentialsMatcher);
        return thirdRealm;
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
