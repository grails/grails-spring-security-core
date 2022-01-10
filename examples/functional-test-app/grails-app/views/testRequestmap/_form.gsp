<div class="fieldcontain ${hasErrors(bean: testRequestmap, field: 'url', 'error')} required">
	<label for="url">Url <span class="required-indicator">*</span></label>
	<g:textField name="url" required="" value="${testRequestmap?.url}"/>
</div>

<div class="fieldcontain ${hasErrors(bean: testRequestmap, field: 'configAttribute', 'error')} required">
	<label for="configAttribute">Config Attribute <span class="required-indicator">*</span></label>
	<g:textField name="configAttribute" required="" value="${testRequestmap?.configAttribute}"/>
</div>

<div class="fieldcontain ${hasErrors(bean: testRequestmap, field: 'httpMethod', 'error')} ">
	<label for="httpMethod">HTTP Method</label>
	<g:select name="httpMethod" from="${org.springframework.http.HttpMethod.values()}"
	          keys="${org.springframework.http.HttpMethod.values()*.name()}"
	          value="${testRequestmap?.httpMethod?.name()}" noSelection="['': '']"/>
</div>
