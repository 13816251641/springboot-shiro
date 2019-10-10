package com.lujieni.springbootshiro.config;

import com.lujieni.springbootshiro.mapper.UserMapper;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.LinkedHashMap;
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
    public DefaultWebSecurityManager getDefaultWebSecurityManager(UserRealm userRealm){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        //关联relam
        securityManager.setRealm(userRealm);
        return securityManager;
    }

    /**
     * 创建Realm
     */
    @Bean
    public UserRealm getUserRealm(){
        return new UserRealm();
    }











}
