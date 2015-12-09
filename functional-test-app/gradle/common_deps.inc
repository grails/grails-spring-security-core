	compile 'org.grails.plugins:cache'
	compile 'org.grails:grails-dependencies'
	compile 'org.grails:grails-web-boot'
	compile 'org.hibernate:hibernate-ehcache'
	compile 'org.springframework.boot:spring-boot-autoconfigure'
	compile 'org.springframework.boot:spring-boot-starter-logging'
	compile 'org.springframework.boot:spring-boot-starter-tomcat'

	String pluginVersion = file('../version.txt').text.trim()
	compile 'org.grails.plugins:spring-security-core:' + pluginVersion
	compile 'org.grails.plugins:spring-security-appinfo:3.0.0'

	runtime 'org.grails.plugins:asset-pipeline'

	testCompile 'org.grails:grails-plugin-testing'
	testCompile 'org.grails.plugins:geb'

	//	testCompile 'com.github.detro:phantomjsdriver:1.2.0'
	testCompile 'com.codeborne:phantomjsdriver:1.2.1' // TODO switch back to com.github.detro:phantomjsdriver when this
	                                                  // issue is resolved: https://github.com/detro/ghostdriver/issues/397

	String seleniumVersion = '2.47.1'
	['chrome', 'firefox', 'htmlunit'].each { String name ->
		testCompile "org.seleniumhq.selenium:selenium-${name}-driver:$seleniumVersion"
	}

	testCompile 'org.gebish:geb-core:0.12.1'

	console 'org.grails:grails-console'
}
