package test

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class TestRequestmap {

	String urlPattern
	String rolePattern

	static constraints = {
		urlPattern blank: false, unique: true
		rolePattern blank: false
	}
}
