
<%@ page import="com.testapp.TestRequestmap" %>
<!DOCTYPE html>
<html>
	<head>
		<meta name="layout" content="main">
		<g:set var="entityName" value="${message(code: 'testRequestmap.label', default: 'TestRequestmap')}" />
		<title><g:message code="default.show.label" args="[entityName]" /></title>
	</head>
	<body>
		<a href="#show-testRequestmap" class="skip" tabindex="-1"><g:message code="default.link.skip.label" default="Skip to content&hellip;"/></a>
		<div class="nav" role="navigation">
			<ul>
				<li><a class="home" href="${createLink(uri: '/')}"><g:message code="default.home.label"/></a></li>
				<li><g:link class="list" action="index"><g:message code="default.list.label" args="[entityName]" /></g:link></li>
				<li><g:link class="create" action="create"><g:message code="default.new.label" args="[entityName]" /></g:link></li>
			</ul>
		</div>
		<div id="show-testRequestmap" class="content scaffold-show" role="main">
			<h1><g:message code="default.show.label" args="[entityName]" /></h1>
			<g:if test="${flash.message}">
			<div class="message" role="status">${flash.message}</div>
			</g:if>
			<ol class="property-list testRequestmap">
				<g:if test="${testRequestmapInstance?.url}">
				<li class="fieldcontain">
					<span id="url-label" class="property-label"><g:message code="testRequestmap.url.label" default="Url" /></span>
						<span class="property-value" aria-labelledby="url-label"><g:fieldValue bean="${testRequestmapInstance}" field="url"/></span>
				</li>
				</g:if>
				<g:if test="${testRequestmapInstance?.configAttribute}">
				<li class="fieldcontain">
					<span id="configAttribute-label" class="property-label"><g:message code="testRequestmap.configAttribute.label" default="Config Attribute" /></span>
						<span class="property-value" aria-labelledby="configAttribute-label"><g:fieldValue bean="${testRequestmapInstance}" field="configAttribute"/></span>
				</li>
				</g:if>
				<g:if test="${testRequestmapInstance?.httpMethod}">
				<li class="fieldcontain">
					<span id="httpMethod-label" class="property-label"><g:message code="testRequestmap.httpMethod.label" default="Http Method" /></span>
						<span class="property-value" aria-labelledby="httpMethod-label"><g:fieldValue bean="${testRequestmapInstance}" field="httpMethod"/></span>
				</li>
				</g:if>
			</ol>
			<g:form url="[resource:testRequestmapInstance, action:'delete']" method="DELETE">
				<fieldset class="buttons">
					<g:link class="edit" action="edit" resource="${testRequestmapInstance}"><g:message code="default.button.edit.label" default="Edit" /></g:link>
					<g:actionSubmit class="delete" action="delete" value="${message(code: 'default.button.delete.label', default: 'Delete')}" onclick="return confirm('${message(code: 'default.button.delete.confirm.message', default: 'Are you sure?')}');" />
				</fieldset>
			</g:form>
		</div>
	</body>
</html>
