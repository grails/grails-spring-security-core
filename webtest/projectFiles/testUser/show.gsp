<head>
	<meta name="layout" content="main" />
	<g:set var="entityName" value="${message(code: 'testUser.label', default: 'TestUser')}" />
	<title><g:message code="default.show.label" args="[entityName]" /></title>
</head>

<body>

<div class="nav">
	<span class="menuButton"><a class="home" href="${createLink(uri: '/')}">Home</a></span>
	<span class="menuButton"><g:link class="list" action="list"><g:message code="default.list.label" args="[entityName]" /></g:link></span>
	<span class="menuButton"><g:link class="create" action="create"><g:message code="default.new.label" args="[entityName]" /></g:link></span>
</div>

<div class="body">
	<h1><g:message code="default.show.label" args="[entityName]" /></h1>

	<g:if test="${flash.message}">
	<div class="message">${flash.message}</div>
	</g:if>

	<div class="dialog">
	<table>
	<tbody>

		<tr class="prop">
			<td valign="top" class="name"><g:message code="testUser.id.label" default="Id" /></td>
			<td valign="top" class="value" id='userId'>${fieldValue(bean: person, field: "id")}</td>
		</tr>

		<tr class="prop">
			<td valign="top" class="name"><g:message code="testUser.username.label" default="Username" /></td>
			<td valign="top" class="value" id='username'>${fieldValue(bean: person, field: "username")}</td>
		</tr>

		<tr class="prop">
			<td valign="top" class="name"><g:message code="testUser.enabled.label" default="Enabled" /></td>
			<td valign="top" class="value" id='userEnabled'><g:formatBoolean boolean="${person?.enabled}" /></td>
		</tr>

		<tr class="prop">
			<td valign="top" class="name">Roles:</td>
			<td valign="top" class="value">
			<ul>
				<g:each in="${roleNames}" var='name'>
				<li>${name}</li>
				</g:each>
			</ul>
			</td>
		</tr>

	</tbody>
	</table>
	</div>

	<div class="buttons">
		<g:form>
			<fieldset class="buttons">
				<g:hiddenField name="id" value="${person?.id}" />
				<g:link class="edit" action="edit" id="${person?.id}"><g:message code="default.button.edit.label" default="Edit" /></g:link>
				<g:actionSubmit class="delete" action="delete" value="${message(code: 'default.button.delete.label', default: 'Delete')}" onclick="return confirm('${message(code: 'default.button.delete.confirm.message', default: 'Are you sure?')}');" />
			</fieldset>
		</g:form>
	</div>
</div>
</body>
