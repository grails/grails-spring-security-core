buildscript {
	repositories {
		mavenLocal()
		maven { url 'https://repo.grails.org/grails/core' }
	}
	dependencies {
		classpath "org.grails:grails-gradle-plugin:$grailsVersion"
		classpath 'com.bertramlabs.plugins:asset-pipeline-gradle:2.8.2'
	}
}
