<html>
<head>
	<title>Welcome to Grails</title>
</head>

<body>
<h1>Available Controllers:</h1>
<ul>
    <g:each var="c" in="${grailsApplication.controllerClasses.sort { it.fullName } }">
        <li class="controller"><g:link controller="${c.logicalPropertyName}" action='${c.defaultAction}'>${c.fullName}</g:link></li>
    </g:each>
</ul>
<h1>Application Status</h1>
<ul>
	<li>Environment: ${grails.util.Environment.current.name}</li>
	<li>App profile: ${grailsApplication.config.grails?.profile}</li>
	<li>App version: <g:meta name="info.app.version"/></li>
	<li>Grails version: <g:meta name="info.app.grailsVersion"/></li>
	<li>Groovy version: ${GroovySystem.getVersion()}</li>
	<li>JVM version: ${System.getProperty('java.version')}</li>
	<li>Reloading active: ${grails.util.Environment.reloadingAgentEnabled}</li>
</ul>
<h1>Artefacts</h1>
<ul>
	<li>Controllers: ${grailsApplication.controllerClasses.size()}</li>
	<li>Domains: ${grailsApplication.domainClasses.size()}</li>
	<li>Services: ${grailsApplication.serviceClasses.size()}</li>
	<li>Tag Libraries: ${grailsApplication.tagLibClasses.size()}</li>
</ul>
<h1>Installed Plugins</h1>
<ul>
	<g:each var="plugin" in="${applicationContext.getBean('pluginManager').allPlugins}">
	<li>${plugin.name} - ${plugin.version}</li>
	</g:each>
</ul>
</body>
</html>
