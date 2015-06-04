<div class="fieldcontain ${hasErrors(bean: testRequestmapInstance, field: 'url', 'error')} required">
	<label for="url">
		<g:message code="testRequestmap.url.label" default="Url" />
		<span class="required-indicator">*</span>
	</label>
	<g:textField name="url" required="" value="${testRequestmapInstance?.url}"/>
</div>

<div class="fieldcontain ${hasErrors(bean: testRequestmapInstance, field: 'configAttribute', 'error')} required">
	<label for="configAttribute">
		<g:message code="testRequestmap.configAttribute.label" default="Config Attribute" />
		<span class="required-indicator">*</span>
	</label>
	<g:textField name="configAttribute" required="" value="${testRequestmapInstance?.configAttribute}"/>
</div>

<div class="fieldcontain ${hasErrors(bean: testRequestmapInstance, field: 'httpMethod', 'error')} ">
	<label for="httpMethod">
		<g:message code="testRequestmap.httpMethod.label" default="Http Method" />
	</label>
	<g:select name="httpMethod" from="${org.springframework.http.HttpMethod?.values()}" keys="${org.springframework.http.HttpMethod.values()*.name()}" value="${testRequestmapInstance?.httpMethod?.name()}"  noSelection="['': '']"/>
</div>
