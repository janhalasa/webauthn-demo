package com.github.janhalasa.webauthndemo.web;

import com.github.janhalasa.webauthndemo.AppUser;
import com.github.janhalasa.webauthndemo.service.WebAuthnService;
import jakarta.servlet.http.HttpSession;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class AuthController {

    private final WebAuthnService webAuthnService;

    AuthController(WebAuthnService webAuthnService) {
        this.webAuthnService = webAuthnService;
    }

    @GetMapping("/")
    public String welcomePage() {
        return "index";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/register")
    public String registerUserPage() {
        return "register";
    }

    @PostMapping("/registration/user/init")
    @ResponseBody
    public String registerUser(
            @RequestParam String username,
            @RequestParam String displayName,
            HttpSession session) {
        return this.webAuthnService.registerUser(username, displayName, session);
    }

    @PostMapping("/registration/user/finish")
    @ResponseBody
    public ModelAndView finishRegistration(
            @RequestParam String credential,
            @RequestParam String username,
            @RequestParam String credentialName,
            HttpSession session) {
        return this.webAuthnService.saveRegistration(credential, username, credentialName, session);
    }

    @PostMapping("/registration/credential")
    @ResponseBody
    public String newAuthRegistration(
            @RequestParam AppUser user,
            HttpSession session) {
        return this.webAuthnService.createDataForPasskeyRegistration(user, session);
    }

    @PostMapping("/authentication/init")
    @ResponseBody
    public String startLogin(@RequestParam(required = false) String username, HttpSession session) {
        return this.webAuthnService.initAuthentication(username, session);
    }

    @PostMapping("/authentication/finish")
    public String finishAuthentication(
            @RequestParam String credential,
            @RequestParam String username,
            Model model,
            HttpSession session) {
        return this.webAuthnService.finishAuthentication(credential, username, model, session);
    }
}
