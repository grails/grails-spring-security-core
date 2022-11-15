<html>
	<head>
		<title>Create TestRequestmap</title>
	</head>
	<body>
		<div class="nav" role="navigation">
			<ul>
				<li><a class="home" href="${createLink(uri: '/')}">Home</a></li>
				<li><g:link class="list">TestRequestmap List</g:link></li>
			</ul>
		</div>
		<div id="create-testRequestmap" class="content scaffold-create" role="main">
			<h1>Create TestRequestmap</h1>
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
			<g:form url="[resource:testRequestmap, action:'save']" >
				<fieldset class="form">
					<g:render template="form"/>
				</fieldset>
				<fieldset class="buttons">
					<g:submitButton name="create" class="save" value='Create' />
				</fieldset>
			</g:form>
		</div>
	</body>
</html>
