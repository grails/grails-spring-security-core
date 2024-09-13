<html>
	<head>
		<title>Grails Runtime Exception</title>
	</head>
	<body>
		<g:if test="${Throwable.isInstance(exception)}">
			<g:renderException exception="${exception}" />
		</g:if>
		<g:elseif test="${request.getAttribute('jakarta.servlet.error.exception')}">
			<g:renderException exception="${request.getAttribute('jakarta.servlet.error.exception')}" />
		</g:elseif>
		<g:else>
			<ul class="errors">
				<li>An error has occurred</li>
				<li>Exception: ${exception}</li>
				<li>Message: ${message}</li>
				<li>Path: ${path}</li>
			</ul>
		</g:else>
	</body>
</html>
