<html>
<head>
	<title>Show TestUser</title>
</head>

<body>

<div class="nav">
	<span class="menuButton"><a class="home" href="${createLink(uri: '/')}">Home</a></span>
	<span class="menuButton"><g:link class="list">TestUser List</g:link></span>
	<span class="menuButton"><g:link class="create" action="create">New TestUser</g:link></span>
</div>

<div class="body">
	<h1>Show TestUser</h1>

	<g:if test="${flash.message}">
	<div class="message">${flash.message}</div>
	</g:if>

	<div class="dialog">
	<table>
	<tbody>

		<tr class="prop">
			<td valign="top" class="name">ID</td>
			<td valign="top" class="value" id='userId'>${fieldValue(bean: person, field: "id")}</td>
		</tr>

		<tr class="prop">
			<td valign="top" class="name">Username</td>
			<td valign="top" class="value" id='username'>${fieldValue(bean: person, field: "username")}</td>
		</tr>

		<tr class="prop">
			<td valign="top" class="name">Enabled</td>
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
				<g:link class="edit" action="edit" id="${person?.id}">Edit</g:link>
				<g:actionSubmit class="delete" action="delete" value='Delete' onclick="return confirm('Are you sure?');" />
			</fieldset>
		</g:form>
	</div>
</div>
</body>
</html>
