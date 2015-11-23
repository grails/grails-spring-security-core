<html>
	<head>
		<title>Grails Runtime Exception</title>
	</head>
	<body>
		<g:if test="${Throwable.isInstance(exception)}">
			<g:renderException exception="${exception}" />
		</g:if>
		<g:elseif test="${request.getAttribute('javax.servlet.error.exception')}">
			<g:renderException exception="${request.getAttribute('javax.servlet.error.exception')}" />
		</g:elseif>
	</body>
</html>
