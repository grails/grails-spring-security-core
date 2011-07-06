import org.springframework.web.filter.DelegatingFilterProxy

eventWebXmlEnd = { String filename ->
	try {
		fixWebXml()
	}
	catch (e) {
		e.printStackTrace()
	}
}

private void fixWebXml() {
	def SpringSecurityUtils = classLoader.loadClass(
		'org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils')

	def conf = SpringSecurityUtils.securityConfig
	if (!conf || !conf.active) {
		return
	}

	String xml = webXmlFile.text

	def root = new XmlParser().parseText(xml)

	def filterMappings = root.'filter-mapping'

	// position the security filter after the last of these,
	// but also move anything in-between to after the security filter
	List positions = []
	filterMappings.eachWithIndex { fm, i ->
		['charEncodingFilter', 'hiddenHttpMethod', 'grailsWebRequest'].each {
			if (fm.'filter-name'.text() == it) positions << i
		}
	}

	List indexesToMove = new ArrayList((positions.min()..positions.max()))
	indexesToMove.removeAll positions

	def mappingPosition = filterMappings[positions.max()]
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
			'dispatcher'('ERROR')
			'dispatcher'('FORWARD')
			'dispatcher'('REQUEST')
		}
	}

	def toMove = indexesToMove.collect { filterMappings[it] }

	def filterChain = root.children().find {
		it.name() == 'filter-mapping' &&
		it.children()[0].text() == 'springSecurityFilterChain' }
	int newPosition = root.children().indexOf(filterChain)

	toMove.each {
		root.children().remove(it)
		root.children().add(newPosition, it)
	}

	webXmlFile.withWriter { it << xmlToString(root) }
}

private String xmlToString(xml) {
	def writer = new StringWriter()
	def printer = new XmlNodePrinter(new PrintWriter(writer))
	printer.preserveWhitespace = true
	printer.print xml
	writer.toString()
}
