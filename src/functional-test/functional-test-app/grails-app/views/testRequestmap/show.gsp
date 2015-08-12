<html>
	<head>
		<title>Show TestRequestmap</title>
	</head>
	<body>
		<div class="nav" role="navigation">
			<ul>
				<li><a class="home" href="${createLink(uri: '/')}">Home</a></li>
				<li><g:link class="list">TestRequestmap List</g:link></li>
				<li><g:link class="create" action="create">New TestRequestmap</g:link></li>
			</ul>
		</div>
		<div id="show-testRequestmap" class="content scaffold-show" role="main">
			<h1>Show TestRequestmap</h1>
			<g:if test="${flash.message}">
			<div class="message" role="status">${flash.message}</div>
			</g:if>
			<ol class="property-list testRequestmap">
				<g:if test="${testRequestmapInstance?.url}">
				<li class="fieldcontain">
					<span id="url-label" class="property-label">URL</span>
					<span class="property-value" aria-labelledby="url-label"><g:fieldValue bean="${testRequestmapInstance}" field="url"/></span>
				</li>
				</g:if>
				<g:if test="${testRequestmapInstance?.configAttribute}">
				<li class="fieldcontain">
					<span id="configAttribute-label" class="property-label">Config Attribute</span>
					<span class="property-value" aria-labelledby="configAttribute-label"><g:fieldValue bean="${testRequestmapInstance}" field="configAttribute"/></span>
				</li>
				</g:if>
				<g:if test="${testRequestmapInstance?.httpMethod}">
				<li class="fieldcontain">
					<span id="httpMethod-label" class="property-label">HTTP Method</span>
					<span class="property-value" aria-labelledby="httpMethod-label"><g:fieldValue bean="${testRequestmapInstance}" field="httpMethod"/></span>
				</li>
				</g:if>
			</ol>
			<g:form url="[resource:testRequestmapInstance, action:'delete']" method="DELETE">
				<fieldset class="buttons">
					<g:link class="edit" action="edit" resource="${testRequestmapInstance}">Edit</g:link>
					<g:actionSubmit class="delete" action="delete" value='Delete' onclick="return confirm('Are you sure?');" />
				</fieldset>
			</g:form>
		</div>
	</body>
</html>
