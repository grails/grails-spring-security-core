<head>
	<meta name="layout" content="main" />
	<g:set var="entityName" value="${message(code: 'testUser.label', default: 'TestUser')}" />
	<title><g:message code="default.create.label" args="[entityName]" /></title>
</head>

<body>

<div class="nav">
	<span class="menuButton"><a class="home" href="${createLink(uri: '/')}">Home</a></span>
	<span class="menuButton"><g:link class="list" action="list"><g:message code="default.list.label" args="[entityName]" /></g:link></span>
</div>

<div class="body">
	<h1><g:message code="default.create.label" args="[entityName]" /></h1>

	<g:if test="${flash.message}">
	<div class="message">${flash.message}</div>
	</g:if>

	<g:hasErrors bean="${testUserInstance}">
	<div class="errors">
	<g:renderErrors bean="${testUserInstance}" as="list" />
	</div>
	</g:hasErrors>

	<g:form action="save">

	<div class="dialog">
	<table>
	<tbody>

		<tr class="prop">
			<td valign="top" class="name">
				<label for="username"><g:message code="testUser.username.label" default="Username" /></label>
			</td>
			<td valign="top" class="value ${hasErrors(bean: testUserInstance, field: 'username', 'errors')}">
				<g:textField name="username" value="${testUserInstance?.username}" />
			</td>
		</tr>

		<tr class="prop">
			<td valign="top" class="name">
				<label for="password"><g:message code="testUser.password.label" default="Password" /></label>
			</td>
			<td valign="top" class="value ${hasErrors(bean: testUserInstance, field: 'password', 'errors')}">
				<g:passwordField name="password" value="${testUserInstance?.password}" />
			</td>
		</tr>

		<tr class="prop">
			<td valign="top" class="name">
				<label for="enabled"><g:message code="testUser.enabled.label" default="Enabled" /></label>
			</td>
			<td valign="top" class="value ${hasErrors(bean: testUserInstance, field: 'enabled', 'errors')}">
				<g:checkBox name="enabled" value="${testUserInstance?.enabled}" />
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
		<span class="button"><g:submitButton name="create" class="save" value="${message(code: 'default.button.create.label', default: 'Create')}" /></span>
	</div>
	</g:form>
</div>
</body>

