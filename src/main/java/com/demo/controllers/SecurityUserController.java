package com.demo.controllers;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import com.demo.model.SecurityUser;

@Controller
public class SecurityUserController {

	@Autowired
	JdbcUserDetailsManager jdbcUserDetailsManager;

	@GetMapping("/login")
	public String login(Model model, String error, String logout) {
		if (error != null)
			model.addAttribute("errorMsg", "Your username and password are invalid.");
		if (logout != null)
			model.addAttribute("msg", "You have been logged out successfully.");
		return "login";
	}

	@GetMapping("/register")
	public ModelAndView register() {
		return new ModelAndView("registration", "user", new SecurityUser());
	}

	@PostMapping("/register")
	public ModelAndView processRegister(@ModelAttribute("user") SecurityUser securityUserObject) {
		// authorities to be granted
		List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
		authorities.add(new SimpleGrantedAuthority(securityUserObject.getUserRole()));
		User user = new User(securityUserObject.getUsername(), securityUserObject.getPassword(), authorities);
		jdbcUserDetailsManager.createUser(user);
		return new ModelAndView("redirect:/welcome");
	}
}
