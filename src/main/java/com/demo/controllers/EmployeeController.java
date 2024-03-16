package com.demo.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import com.demo.model.Employee;
import com.demo.service.EmployeeService;

@Controller
public class EmployeeController {

	@Autowired
	EmployeeService employeeService;

	@GetMapping("/welcome")
	public ModelAndView firstPage() {
		return new ModelAndView("welcome");
	}

	@GetMapping("/addNewEmployee")
	public ModelAndView show() {
		return new ModelAndView("addEmployee", "emp", new Employee());
	}

	@PostMapping("/addNewEmployee")
	public ModelAndView processRequest(@ModelAttribute("emp") Employee emp) {
		
		employeeService.insertEmployee(emp);
		List<Employee> employees = employeeService.getAllEmployees();
		ModelAndView model = new ModelAndView("getEmployees");
		model.addObject("employees", employees);
		return model;
	}

	@GetMapping("/getEmployees")
	public ModelAndView getEmployees() {
		List<Employee> employees = employeeService.getAllEmployees();
		ModelAndView model = new ModelAndView("getEmployees");
		model.addObject("employees", employees);
		return model;
	}

}
