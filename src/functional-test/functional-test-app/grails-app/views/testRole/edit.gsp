<html>
	<head>
		<title>Edit TestRole</title>
	</head>
	<body>
		<div class="nav" role="navigation">
			<ul>
				<li><a class="home" href="${createLink(uri: '/')}">Home</a></li>
				<li><g:link class="list">TestRole List</g:link></li>
				<li><g:link class="create" action="create">New TestRole</g:link></li>
			</ul>
		</div>
		<div id="edit-testRole" class="content scaffold-edit" role="main">
			<h1>Edit TestRole</h1>
			<g:if test="${flash.message}">
			<div class="message" role="status">${flash.message}</div>
			</g:if>
			<g:hasErrors bean="${testRole}">
			<ul class="errors" role="alert">
				<g:eachError bean="${testRole}" var="error">
				<li <g:if test="${error in org.springframework.validation.FieldError}">data-field-id="${error.field}"</g:if>><g:message error="${error}"/></li>
				</g:eachError>
			</ul>
			</g:hasErrors>
			<g:form url="[resource:testRole, action:'update']" method="PUT" >
				<g:hiddenField name="version" value="${testRole?.version}" />
				<fieldset class="form">
					<g:render template="form"/>
				</fieldset>
				<fieldset class="buttons">
					<g:actionSubmit class="save" action="update" value='Update' />
				</fieldset>
			</g:form>
		</div>
	</body>
</html>
