import grails.util.GrailsUtil

import org.springframework.web.filter.DelegatingFilterProxy

eventWebXmlEnd = { String filename ->
	try {
		fixWebXml()
	}
	catch (e) {
		GrailsUtil.deepSanitize e
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

	addNode root.filter[0], {
		'filter' {
			'filter-name'('springSecurityFilterChain')
			'filter-class'(DelegatingFilterProxy.name)
		}
	}

	addNode mappingPosition, {
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

// copy of Node.plus() method from 1.7 since it wasn't there in 1.6
private void addNode(Node n, Closure c) {
	List<Node> list = n.parent().children()
	int afterIndex = list.indexOf(n)
	List<Node> leftOvers = new ArrayList<Node>(list.subList(afterIndex + 1, list.size()))
	list.subList(afterIndex + 1, list.size()).clear()

	Node newNode = new NodeBuilder().invokeMethod('dummyNode', c)
	for (Node child : newNode.children()) {
		n.parent().appendNode(child.name(), child.attributes(), child.value())
	}

	for (Node child : leftOvers) {
		n.parent().children().add(child)
	}
}
