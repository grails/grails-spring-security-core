package test

import grails.web.CamelCaseUrlConverter
import grails.web.HyphenatedUrlConverter
import grails.web.UrlConverter

class HackUrlConverter implements UrlConverter {

	private UrlConverter hyphenated = new HyphenatedUrlConverter()
	private UrlConverter camelCaseConverter = new CamelCaseUrlConverter()
	private UrlConverter converter = camelCaseConverter

	String toUrlElement(String propertyOrClassName) {
		converter.toUrlElement propertyOrClassName
	}

	void useHyphenated() {
		converter = hyphenated
	}
}
