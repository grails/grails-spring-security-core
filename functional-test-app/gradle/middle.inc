apply plugin: 'asset-pipeline'
apply plugin: 'org.grails.grails-web'

version '0.1'
group 'functional.test.app'

ext {
	grailsVersion = project.grailsVersion
}

repositories {
	mavenLocal()
	maven { url 'https://repo.grails.org/grails/core' }
}

dependencyManagement {
	imports {
		mavenBom "org.grails:grails-bom:$grailsVersion"
	}
	applyMavenExclusions false
}

dependencies {
