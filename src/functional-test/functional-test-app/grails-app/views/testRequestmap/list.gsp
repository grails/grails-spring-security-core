<html>
	<head>
		<title>TestRequestmap List</title>
	</head>
	<body>
		<div class="nav" role="navigation">
			<ul>
				<li><a class="home" href="${createLink(uri: '/')}">Home</a></li>
				<li><g:link class="create" action="create">New TestRequestmap</g:link></li>
			</ul>
		</div>
		<div id="list-testRequestmap" class="content scaffold-list" role="main">
			<h1>TestRequestmap List</h1>
			<g:if test="${flash.message}">
			<div class="message" role="status">${flash.message}</div>
			</g:if>
			<table>
				<thead>
					<tr>
						<g:sortableColumn property="url" title='URL' />
						<g:sortableColumn property="configAttribute" title='Config Attribute' />
						<g:sortableColumn property="httpMethod" title='HTTP Method' />
					</tr>
				</thead>
				<tbody>
    				<g:each in="${testRequestmapInstanceList}" status="i" var="testRequestmapInstance">
					<tr class="${(i % 2) == 0 ? 'even' : 'odd'}">
						<td><g:link action="show" id="${testRequestmapInstance.id}">${fieldValue(bean: testRequestmapInstance, field: "url")}</g:link></td>
						<td>${fieldValue(bean: testRequestmapInstance, field: "configAttribute")}</td>
						<td>${fieldValue(bean: testRequestmapInstance, field: "httpMethod")}</td>
					</tr>
	    			</g:each>
				</tbody>
			</table>
			<div class="pagination">
				<g:paginate total="${testRequestmapInstanceCount ?: 0}" />
			</div>
		</div>
	</body>
</html>
