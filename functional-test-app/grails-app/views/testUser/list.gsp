<html>
<head>
	<g:set var="entityName" value="${message(code: 'testUser.label', default: 'TestUser')}" />
	<title><g:message code="default.list.label" args="[entityName]" /></title>
</head>

<body>

<div class="nav">
	<span class="menuButton"><a class="home" href="${createLink(uri: '/')}">Home</a></span>
	<span class="menuButton"><g:link class="create" action="create"><g:message code="default.new.label" args="[entityName]" /></g:link></span>
</div>

<div class="body">

	<h1><g:message code="default.list.label" args="[entityName]" /></h1>

	<g:if test="${flash.message}">
	<div class="message">${flash.message}</div>
	</g:if>

	<div class="list">
	<table>
		<thead>
		<tr>
			<g:sortableColumn property="id" title="${message(code: 'testUser.id.label', default: 'Id')}" />
			<g:sortableColumn property="username" title="${message(code: 'testUser.username.label', default: 'Username')}" />
			<g:sortableColumn property="enabled" title="${message(code: 'testUser.enabled.label', default: 'Enabled')}" />
		</tr>
		</thead>

		<tbody>
		<g:each in="${personList}" status="i" var="person">
		<tr class="${(i % 2) == 0 ? 'odd' : 'even'}">
			<td><g:link action="show" id="${person.id}">${fieldValue(bean: person, field: "id")}</g:link></td>
			<td>${fieldValue(bean: person, field: "username")}</td>
			<td><g:formatBoolean boolean="${person.enabled}" /></td>
		</tr>
		</g:each>
		</tbody>
	</table>
	</div>

	<div class="paginateButtons">
		<g:paginate total="${personCount}" />
	</div>

</div>
</body>
</html>
