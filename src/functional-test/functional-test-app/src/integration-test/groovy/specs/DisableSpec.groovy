package specs

import pages.IndexPage

class DisableSpec extends AbstractSecuritySpec {

	def 'lock account'() {

		when:
			login 'user1', 'p4ssw0rd'

		then:
			at IndexPage

		when:
			go 'secureAnnotated'

		then:
			assertContentContains 'you have ROLE_ADMIN'

		when:
			logout()

		then:
			'false' == getContent('hack/getUserProperty?user=user1&propName=accountLocked')

		when:
			go 'hack/setUserProperty?user=user1&accountLocked=true'

		then:
			'true' == getContent('hack/getUserProperty?user=user1&propName=accountLocked')

		when:
			login 'user1', 'p4ssw0rd'

		then:
			assertContentContains 'accountLocked'

		// reset
		when:
			go 'hack/setUserProperty?user=user1&accountLocked=false'

		then:
			'false' == getContent('hack/getUserProperty?user=user1&propName=accountLocked')
	}

	def 'disable account'() {

		when:
			login 'user1', 'p4ssw0rd'

		then:
			at IndexPage

		when:
			go 'secureAnnotated'

		then:
			assertContentContains 'you have ROLE_ADMIN'

		when:
			logout()

		then:
			'true' == getContent('hack/getUserProperty?user=user1&propName=enabled')

		when:
			go 'hack/setUserProperty?user=user1&enabled=false'

		then:
			'false' == getContent('hack/getUserProperty?user=user1&propName=enabled')

		when:
			login 'user1', 'p4ssw0rd'

		then:
			assertContentContains 'accountDisabled'

		// reset
		when:
			go 'hack/setUserProperty?user=user1&enabled=true'

		then:
			'true' == getContent('hack/getUserProperty?user=user1&propName=enabled')
	}

	def 'expire account'() {

		when:
			login 'user1', 'p4ssw0rd'

		then:
			at IndexPage

		when:
			go 'secureAnnotated'

		then:
			assertContentContains 'you have ROLE_ADMIN'

		when:
			logout()

		then:
			'false' == getContent('hack/getUserProperty?user=user1&propName=accountExpired')

		when:
			go 'hack/setUserProperty?user=user1&accountExpired=true'

		then:
			'true' == getContent('hack/getUserProperty?user=user1&propName=accountExpired')

		when:
			login 'user1', 'p4ssw0rd'

		then:
			assertContentContains 'accountExpired'

		// reset
		when:
			go 'hack/setUserProperty?user=user1&accountExpired=false'

		then:
			'false' == getContent('hack/getUserProperty?user=user1&propName=accountExpired')
	}

	def 'expire password'() {

		when:
			login 'user1', 'p4ssw0rd'

		then:
			at IndexPage

		when:
			go 'secureAnnotated'

		then:
			assertContentContains 'you have ROLE_ADMIN'

		when:
			logout()

		then:
			'false' == getContent('hack/getUserProperty?user=user1&propName=passwordExpired')

		when:
			go 'hack/setUserProperty?user=user1&passwordExpired=true'

		then:
			'true' == getContent('hack/getUserProperty?user=user1&propName=passwordExpired')

		when:
			login 'user1', 'p4ssw0rd'

		then:
			assertContentContains 'passwordExpired'

		// reset
		when:
			go 'hack/setUserProperty?user=user1&passwordExpired=false'

		then:
			'false' == getContent('hack/getUserProperty?user=user1&propName=passwordExpired')
	}
}
