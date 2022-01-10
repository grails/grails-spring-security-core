package demo

import groovy.transform.EqualsAndHashCode
import groovy.transform.ToString
import grails.compiler.GrailsCompileStatic

@GrailsCompileStatic
@EqualsAndHashCode(includes='entry')
@ToString(includes='entry', includeNames=true, includePackage=false)
class RoleHierarchyEntry implements Serializable {

	private static final long serialVersionUID = 1

	String entry

	static constraints = {
		entry nullable: false, blank: false, unique: true
	}

	static mapping = {
		cache true
	}
}
