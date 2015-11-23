<html>
<head>
	<title>Create TestUser</title>
</head>

<body>

<div class="nav">
	<span class="menuButton"><a class="home" href="${createLink(uri: '/')}">Home</a></span>
	<span class="menuButton"><g:link class="list">TestUser List</g:link></span>
</div>

<div class="body">
	<h1>Create TestUser</h1>

	<g:if test="${flash.message}">
	<div class="message">${flash.message}</div>
	</g:if>

	<g:hasErrors bean="${testUser}">
	<div class="errors">
	<g:renderErrors bean="${testUser}" as="list" />
	</div>
	</g:hasErrors>

	<g:form action="save">

	<div class="dialog">
	<table>
	<tbody>

		<tr class="prop">
			<td valign="top" class="name">
				<label for="username">Username</label>
			</td>
			<td valign="top" class="value ${hasErrors(bean: testUser, field: 'username', 'errors')}">
				<g:textField name="username" value="${testUser?.username}" />
			</td>
		</tr>

		<tr class="prop">
			<td valign="top" class="name">
				<label for="password">Password</label>
			</td>
			<td valign="top" class="value ${hasErrors(bean: testUser, field: 'password', 'errors')}">
				<g:passwordField name="password" value="${testUser?.password}" />
			</td>
		</tr>

		<tr class="prop">
			<td valign="top" class="name">
				<label for="enabled">Enabled</label>
			</td>
			<td valign="top" class="value ${hasErrors(bean: testUser, field: 'enabled', 'errors')}">
				<g:checkBox name="enabled" value="${testUser?.enabled}" />
			</td>
		</tr>

		<tr class="prop">
			<td valign="top" class="name" align="left">Assign Roles:</td>
		</tr>

		<g:each var='auth' in="${authorityList}">
		<tr>
			<td valign="top" class="name" align="left">${auth.authority.encodeAsHTML()}</td>
			<td align="left"><g:checkBox name="${auth.authority}" id="${auth.authority}"/></td>
		</tr>
		</g:each>

	</tbody>
	</table>
	</div>

	<div class="buttons">
		<span class="button"><g:submitButton name="create" class="save" value='Create' /></span>
	</div>
	</g:form>
</div>
</body>
</html>
