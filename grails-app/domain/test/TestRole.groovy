package test

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class TestRole {

	String auth
	String description

	static constraints = {
		auth blank: false, unique: true
	}
}
