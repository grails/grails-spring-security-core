grails.servlet.version = "3.0" // Change depending on target container compliance (2.5 or 3.0)
grails.project.work.dir = 'target'


grails.project.work.dir = "target/work"
grails.project.target.level = 1.6
grails.project.source.level = 1.6
//grails.project.war.file = "target/${appName}-${appVersion}.war"

grails.project.forkDISABLED = [
    // configure settings for compilation JVM, note that if you alter the Groovy version forked compilation is required
    //  compile: [maxMemory: 256, minMemory: 64, debug: false, maxPerm: 256, daemon:true],

    // configure settings for the test-app JVM, uses the daemon by default
    test: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, daemon:true],
    // configure settings for the run-app JVM
    run: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, forkReserve:false],
    // configure settings for the run-war JVM
    war: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256, forkReserve:false],
    // configure settings for the Console UI JVM
    console: [maxMemory: 768, minMemory: 64, debug: false, maxPerm: 256]
]

grails.project.dependency.resolver = "maven" // or ivy
grails.project.dependency.resolution = {
    // inherit Grails' default dependencies
    inherits("global") {
        // specify dependency exclusions here; for example, uncomment this to disable ehcache:
        // excludes 'ehcache'
    }
    log "error" // log level of Ivy resolver, either 'error', 'warn', 'info', 'debug' or 'verbose'
    checksums true // Whether to verify checksums on resolve
    legacyResolve false // whether to do a secondary resolve on plugin installation, not advised and here for backwards compatibility

    repositories {
mavenRepo 'http://repo.spring.io/milestone' // TODO remove

        inherits true // Whether to inherit repository definitions from plugins

        grailsPlugins()
        grailsHome()
        mavenLocal()
        grailsCentral()
        mavenCentral()
        // uncomment these (or add new ones) to enable remote dependency resolution from public Maven repositories
        //mavenRepo "http://repository.codehaus.org"
        //mavenRepo "http://download.java.net/maven/2/"
        //mavenRepo "http://repository.jboss.com/maven2/"
    }

    
	String gebVersion = '0.9.3'
	String seleniumVersion = '2.42.2'

	dependencies {
		test "org.seleniumhq.selenium:selenium-chrome-driver:$seleniumVersion"
		test "org.seleniumhq.selenium:selenium-firefox-driver:$seleniumVersion"
		test 'com.github.detro:phantomjsdriver:1.2.0', {
			transitive = false
		}
        test "org.gebish:geb-spock:0.9.3"
        // specify dependencies here under either 'build', 'compile', 'runtime', 'test' or 'provided' scopes e.g.
        // runtime 'mysql:mysql-connector-java:5.1.27'
        // runtime 'org.postgresql:postgresql:9.3-1100-jdbc41'
    }

    plugins {
		test ":geb:$gebVersion"

		runtime ":spring-security-core:2.0-SNAPSHOT"

        // plugins for the build system only
        build ":tomcat:7.0.54"

        // plugins for the compile step
        compile ":scaffolding:2.0.3"
        compile ':cache:1.1.7'

        // plugins needed at runtime but not for compilation
        runtime ":hibernate:3.6.10.16" // or ":hibernate4:4.3.5.1"
        runtime ":database-migration:1.4.0"
        runtime ":jquery:1.11.1"
        runtime ":resources:1.2.8"
        // Uncomment these (or add new ones) to enable additional resources capabilities
        //runtime ":zipped-resources:1.0.1"
        //runtime ":cached-resources:1.1"
        //runtime ":yui-minify-resources:0.1.5"

        // An alternative to the default resources plugin is the asset-pipeline plugin
        //compile ":asset-pipeline:1.6.1"

        // Uncomment these to enable additional asset-pipeline capabilities
        //compile ":sass-asset-pipeline:1.5.5"
        //compile ":less-asset-pipeline:1.5.3"
        //compile ":coffee-asset-pipeline:1.5.0"
        //compile ":handlebars-asset-pipeline:1.3.0.1"
    }
}


def file = new File('testconfig')
String testconfig = file.exists() ? file.text.trim() : ''
switch (testconfig) {
	case 'annotation':
		grails.testing.patterns = ['Role', 'User', 'AnnotationSecurity']
		break
	case 'basic':
		grails.testing.patterns = ['Role', 'User', 'BasicAuthSecurity']
		break
	case 'bcrypt':
		grails.testing.patterns = ['BCrypt']
		break
	case 'misc':
		grails.testing.patterns = ['Misc', 'Disable']
		break
	case 'requestmap':
		grails.testing.patterns = ['Requestmap', 'Role', 'User', 'RequestmapSecurity']
		break
	case 'static':
		grails.testing.patterns = ['Role', 'User', 'StaticSecurity']
		break
}
grails.server.port.http = 8238
