package com.lujieni.springbootshiro.com.lujieni.springbootshiro.controller;


import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.RequiresAuthentication;
import org.apache.shiro.authz.annotation.RequiresGuest;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.HashMap;
import java.util.Map;


@Controller
@Slf4j
public class UserController {

    private static final String LOGIN="login";

    /* @RequiresGuest
       游客即可登录 在ShiroConfig中的权限配置 > 注解申明的权限配置,
       即在ShiroConfig中配置了需要登录,注解中配置无需登录,听从ShiroConfig
       中配置的,并且会转跳到ShiroConfig中配置的登录界面
     */
    /*
       @RequiresAuthentication
       需要登录才能访问 如果权限是交给ShiroConfig去判断的,
       会跳转到setLoginUrl配置的地址,否则不会
     */
    /*
        @RequiresRoles(value = {"admin"})需要admin角色才能登录
        如果权限是被ShiroConfig中的配置捕获,会先跳转到登录界面的
     */
    @RequiresGuest
    @GetMapping("/hello")
    @ResponseBody
    public String hello(){
        return "hello";
    }

    @GetMapping(value = "/testThymeleaf")
    public String testThymeleaf(Model model){
        Map<String,Integer> map = new HashMap<>();
        map.put("a",1);
        model.addAttribute("name","黑马程序员");
        return "test";
    }

    @GetMapping(value = "/add")
    public String add(){
        return "/user/add";
    }

    @GetMapping(value = "/update")
    public String update(Model model){
        return "/user/update";
    }

    @GetMapping(value="/toLogin")
    public String toLogin(){
        return "/login";
    }

    @GetMapping(value="/noAuth")
    public String noAuth(){
        return "/noAuth";
    }

    @PostMapping(value="/login")
    public String login(String name , String password, Model model){
        /* 使用shiro编写认证操作 取subject*/
        Subject currentUser = SecurityUtils.getSubject();
        //判断用户是否登录过
        if(!currentUser.isAuthenticated()){
            //封装用户数据
            UsernamePasswordToken token = new UsernamePasswordToken(name,password);
            //执行登录方法
            try {
                currentUser.login(token);
                //登录成功 重定向
                return "redirect:/testThymeleaf";
            } catch (UnknownAccountException e) {
                model.addAttribute("msg","用户名不存在");
                return LOGIN;
            }catch (IncorrectCredentialsException e){
                model.addAttribute("msg","密码错误");
                return LOGIN;
            }catch (AuthenticationException e) {
                model.addAttribute("msg",e.getMessage());
                return LOGIN;
            }
        }
        log.info("已登录");
        return "redirect:/testThymeleaf";
    }
}


