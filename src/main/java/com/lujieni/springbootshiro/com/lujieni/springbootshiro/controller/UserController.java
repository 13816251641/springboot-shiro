package com.lujieni.springbootshiro.com.lujieni.springbootshiro.controller;


import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;


@Controller
@Slf4j
public class UserController {

    @RequestMapping("/testThymeleaf")
    public String testThymeleaf(Model model){
        model.addAttribute("name","黑马程序员");
        return "test";
    }

    @RequestMapping("/add")
    public String add(){
        return "/user/add";
    }

    @RequestMapping("/update")
    public String update(Model model){
        return "/user/update";
    }

    @RequestMapping("/toLogin")
    public String toLogin(){
        return "/login";
    }

    @RequestMapping("/noAuth")
    public String noAuth(){
        return "/noAuth";
    }

    @RequestMapping("/login")
    public String login(String name , String password, Model model){
        /*
            使用shiro编写认证操作
         */
        //获取subject12322v3.0
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
                //e.printStackTrace();
                model.addAttribute("msg","用户名不存在");
                return "login";
            }catch (IncorrectCredentialsException e){
                model.addAttribute("msg","密码错误");
                return "login";
            }
        }
        log.info("已登录");
        return "redirect:/testThymeleaf";
    }
}


