<html>
	<head>
		<title>Edit TestRequestmap</title>
	</head>
	<body>
		<div class="nav" role="navigation">
			<ul>
				<li><a class="home" href="${createLink(uri: '/')}">Home</a></li>
				<li><g:link class="list">TestRequestmap List</g:link></li>
				<li><g:link class="create" action="create">New TestRequestmap</g:link></li>
			</ul>
		</div>
		<div id="edit-testRequestmap" class="content scaffold-edit" role="main">
			<h1>Edit TestRequestmap</h1>
			<g:if test="${flash.message}">
			<div class="message" role="status">${flash.message}</div>
			</g:if>
			<g:hasErrors bean="${testRequestmap}">
			<ul class="errors" role="alert">
				<g:eachError bean="${testRequestmap}" var="error">
				<li <g:if test="${error in org.springframework.validation.FieldError}">data-field-id="${error.field}"</g:if>><g:message error="${error}"/></li>
				</g:eachError>
			</ul>
			</g:hasErrors>
			<g:form url="[resource:testRequestmap, action:'update']" method="PUT" >
				<g:hiddenField name="version" value="${testRequestmap?.version}" />
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
