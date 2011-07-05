import groovy.xml.StreamingMarkupBuilder

import org.springframework.web.filter.DelegatingFilterProxy

eventWebXmlEnd = { String filename ->

	def SpringSecurityUtils = classLoader.loadClass(
		'org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils')

	def conf = SpringSecurityUtils.securityConfig
	if (!conf || !conf.active) {
		return
	}

	String xml = webXmlFile.text

	def root = new XmlSlurper().parseText(xml)

	def charEncodingFilterMapping = root.'filter-mapping'.find {
		it.'filter-name'.text() == 'charEncodingFilter' }

	// add the filter-mapping after the Spring character encoding filter
	// or after the last filter if it's not there
	def mappingPosition
	if (charEncodingFilterMapping.size()) {
		mappingPosition = charEncodingFilterMapping
	}
	else {
		mappingPosition = root.filter[-1]
	}

	// the name of the filter matches the name of the Spring bean that it delegates to
	root.filter[0] + {
		'filter' {
			'filter-name'('springSecurityFilterChain')
			'filter-class'(DelegatingFilterProxy.name)
		}
	}

	mappingPosition + {
		'filter-mapping' {
			'filter-name'('springSecurityFilterChain')
			'url-pattern'('/*')
		}
	}

	webXmlFile.withWriter { it << xmlToString(root) }
}

// TODO this is not good; fix
private String xmlToString(xml) {
   def writer = new StringWriter()
   writer << new StreamingMarkupBuilder().bind { mkp.yield xml }

   def sw = new StringWriter()
   def printer = new XmlNodePrinter(new PrintWriter(sw), '\t')
   printer.preserveWhitespace = true
   printer.print new XmlParser().parseText(writer.toString())

   String rendered = sw.toString()
   rendered = rendered.replaceAll('tag0:', '')
   rendered = rendered.replaceAll(':tag0', '')
   rendered
}
