<html>
	<head>
		<title>Show TestRole</title>
	</head>
	<body>
		<div class="nav" role="navigation">
			<ul>
				<li><a class="home" href="${createLink(uri: '/')}">Home</a></li>
				<li><g:link class="list">TestRole List</g:link></li>
				<li><g:link class="create" action="create">New TestRole</g:link></li>
			</ul>
		</div>
		<div id="show-testRole" class="content scaffold-show" role="main">
			<h1>Show TestRole</h1>
			<g:if test="${flash.message}">
			<div class="message" role="status">${flash.message}</div>
			</g:if>
			<ol class="property-list testRole">
				<g:if test="${testRole?.authority}">
				<li class="fieldcontain">
					<span id="authority-label" class="property-label">Authority</span>
					<span class="property-value" aria-labelledby="authority-label"><g:fieldValue bean="${testRole}" field="authority"/></span>
				</li>
				</g:if>
			</ol>
			<g:form url="[resource:testRole, action:'delete']" method="DELETE">
				<fieldset class="buttons">
					<g:link class="edit" action="edit" resource="${testRole}">Edit</g:link>
					<g:actionSubmit class="delete" action="delete" value='Delete' onclick="return confirm('Are you sure?');" />
				</fieldset>
			</g:form>
		</div>
	</body>
</html>
