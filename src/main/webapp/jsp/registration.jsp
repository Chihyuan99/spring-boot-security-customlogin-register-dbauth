<%@taglib uri="http://www.springframework.org/tags/form" prefix="form"%>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; 
charset=ISO-8859-1">
<title>Register User</title>
</head>
<body>
	<h3 style="color: red;">Register New User</h3>
	<div id="registerEmployee">
		<form:form action="/register" method="post" modelAttribute="user">
			<p>
				<label>Enter username</label>
				<form:input path="username" />
			</p>
			<p>
				<label>Enter password</label>
				<form:input path="password" />
			</p>
			<p>
				<label>Enter user role</label>
				<form:select path="userRole">
					<form:option value="ROLE_MGR">Manager</form:option>
					<form:option value="ROLE_DEV">Developer</form:option>
					<form:option value="ROLE_ADMIN">Admin</form:option>
					<form:option value="ROLE_USER">User</form:option>
					<form:option value="ROLE_HRM">Human Resources</form:option>
				</form:select>
			</p>
			<input type="SUBMIT" value="Submit" />
		</form:form>
	</div>
</body>
</html>