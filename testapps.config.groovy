String version = '2.0-RC2'
String grailsHomeRoot = "${System.getProperty('user.home')}/.gvm/grails"
String dotGrailsCommon = "${System.getProperty('user.home')}/.grails"
String projectDirCommon = 'target/testapps/spring-security-test'

v20 {
	grailsVersion = '2.0.4'
	pluginVersion = version
	dotGrails = dotGrailsCommon
	projectDir = projectDirCommon
	grailsHome = grailsHomeRoot + '/' + grailsVersion
}

v21 {
	grailsVersion = '2.1.4' // 2.1.5 has a plugin i18n bug
	pluginVersion = version
	dotGrails = dotGrailsCommon
	projectDir = projectDirCommon
	grailsHome = grailsHomeRoot + '/' + grailsVersion
}

v22 {
	grailsVersion = '2.2.5'
	pluginVersion = version
	dotGrails = dotGrailsCommon
	projectDir = projectDirCommon
	grailsHome = grailsHomeRoot + '/' + grailsVersion
}

v23 {
	grailsVersion = '2.3.8'
	pluginVersion = version
	dotGrails = dotGrailsCommon
	projectDir = projectDirCommon
	grailsHome = grailsHomeRoot + '/' + grailsVersion
}
