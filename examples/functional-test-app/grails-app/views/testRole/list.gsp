<html>
	<head>
		<title>TestRole List</title>
	</head>
	<body>
		<div class="nav" role="navigation">
			<ul>
				<li><a class="home" href="${createLink(uri: '/')}">Home</a></li>
				<li><g:link class="create" action="create">New TestRole</g:link></li>
			</ul>
		</div>
		<div id="list-testRole" class="content scaffold-list" role="main">
			<h1>TestRole List</h1>
			<g:if test="${flash.message}">
			<div class="message" role="status">${flash.message}</div>
			</g:if>
			<table>
				<thead>
					<tr>
						<g:sortableColumn property="authority" title='Authority' />
					</tr>
				</thead>
				<tbody>
    				<g:each in="${testRoles}" status="i" var="testRole">
					<tr class="${(i % 2) == 0 ? 'even' : 'odd'}">
						<td><g:link action="show" id="${testRole.id}">${fieldValue(bean: testRole, field: "authority")}</g:link></td>
					</tr>
	    			</g:each>
				</tbody>
			</table>
			<div class="pagination">
				<g:paginate total="${testRoleCount ?: 0}" />
			</div>
		</div>
	</body>
</html>
