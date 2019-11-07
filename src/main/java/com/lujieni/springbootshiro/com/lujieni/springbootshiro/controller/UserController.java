package com.lujieni.springbootshiro.com.lujieni.springbootshiro.controller;


import com.lujieni.springbootshiro.config.ShiroService;
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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.websocket.Session;
import java.util.HashMap;
import java.util.Map;


@Controller
@Slf4j
public class UserController {

    private static final String LOGIN="login";

    @Autowired
    private ShiroService shiroService;

    /* @RequiresGuest
       游客即可登录 在ShiroConfig中的权限配置 > 注解申明的权限配置,
       即在ShiroConfig中配置了需要登录,注解中配置无需登录,听从ShiroConfig
       中配置的,并且会转跳到ShiroConfig中配置的登录界面
     */

    /*
       @RequiresAuthentication
       需要登录才能访问 如果ShiroConfig中也配置了这个url需要登录才能访问,
       则还会跳转到setLoginUrl配置的地址,否则不会
     */
    /*
        @RequiresRoles(value = {"admin"})需要admin角色才能登录
        如果权限是被ShiroConfig中的配置捕获,会先跳转到登录界面的
     */
    @GetMapping("/hello")
    @ResponseBody
    public String hello(HttpServletRequest request){
        /*这里的实现类是ShiroHttpSession*/
        HttpSession session = request.getSession();
        if(session.getAttribute("age") == null){
            session.setAttribute("age","28");
        }else{
            shiroService.getInfoFromSession();
        }
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

    @GetMapping(value="/info")
    public String info(){
        Subject subject = SecurityUtils.getSubject();
        boolean authenticated = subject.isAuthenticated();
        return "/info";
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
                token.setRememberMe(true);
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

    @GetMapping("/refresh")
    @ResponseBody
    public String  refresh(){
        shiroService.updatePermission();
        return "success";
    }
}


