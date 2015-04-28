<%@ page import="com.testapp.TestRole" %>



<div class="fieldcontain ${hasErrors(bean: testRoleInstance, field: 'authority', 'error')} required">
	<label for="authority">
		<g:message code="testRole.authority.label" default="Authority" />
		<span class="required-indicator">*</span>
	</label>
	<g:textField name="authority" required="" value="${testRoleInstance?.authority}"/>

</div>

