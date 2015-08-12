<div class="fieldcontain ${hasErrors(bean: testRequestmapInstance, field: 'url', 'error')} required">
	<label for="url">Url <span class="required-indicator">*</span></label>
	<g:textField name="url" required="" value="${testRequestmapInstance?.url}"/>
</div>

<div class="fieldcontain ${hasErrors(bean: testRequestmapInstance, field: 'configAttribute', 'error')} required">
	<label for="configAttribute">Config Attribute <span class="required-indicator">*</span></label>
	<g:textField name="configAttribute" required="" value="${testRequestmapInstance?.configAttribute}"/>
</div>

<div class="fieldcontain ${hasErrors(bean: testRequestmapInstance, field: 'httpMethod', 'error')} ">
	<label for="httpMethod">HTTP Method</label>
	<g:select name="httpMethod" from="${org.springframework.http.HttpMethod.values()}"
	          keys="${org.springframework.http.HttpMethod.values()*.name()}"
	          value="${testRequestmapInstance?.httpMethod?.name()}" noSelection="['': '']"/>
</div>
