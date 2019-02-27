package com.poc.oic.controller;

import com.poc.oic.user.User;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.security.Principal;

@Controller
public class RootController {
    @RequestMapping("/")
    @ResponseBody
    public final String home() {
        User user = (User)SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        return "Hello " + user.getUsername() +
                "<br /><br />" +
                "Your access token is: " + user.getToken();
    }
}
