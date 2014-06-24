
<%@ page import="com.testapp.TestRequestmap" %>
<!DOCTYPE html>
<html>
	<head>
		<meta name="layout" content="main">
		<g:set var="entityName" value="${message(code: 'testRequestmap.label', default: 'TestRequestmap')}" />
		<title><g:message code="default.list.label" args="[entityName]" /></title>
	</head>
	<body>
		<a href="#list-testRequestmap" class="skip" tabindex="-1"><g:message code="default.link.skip.label" default="Skip to content&hellip;"/></a>
		<div class="nav" role="navigation">
			<ul>
				<li><a class="home" href="${createLink(uri: '/')}"><g:message code="default.home.label"/></a></li>
				<li><g:link class="create" action="create"><g:message code="default.new.label" args="[entityName]" /></g:link></li>
			</ul>
		</div>
		<div id="list-testRequestmap" class="content scaffold-list" role="main">
			<h1><g:message code="default.list.label" args="[entityName]" /></h1>
			<g:if test="${flash.message}">
				<div class="message" role="status">${flash.message}</div>
			</g:if>
			<table>
			<thead>
					<tr>
					
						<g:sortableColumn property="url" title="${message(code: 'testRequestmap.url.label', default: 'Url')}" />
					
						<g:sortableColumn property="configAttribute" title="${message(code: 'testRequestmap.configAttribute.label', default: 'Config Attribute')}" />
					
						<g:sortableColumn property="httpMethod" title="${message(code: 'testRequestmap.httpMethod.label', default: 'Http Method')}" />
					
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
