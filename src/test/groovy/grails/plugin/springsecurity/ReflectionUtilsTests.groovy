/* Copyright 2006-2015 SpringSource.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package grails.plugin.springsecurity

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class ReflectionUtilsTests extends GroovyTestCase {

	private FakeApplication application

	@Override
	protected void setUp() {
		super.setUp()
		def app = TestUtils.createTestApplication()
		application = ReflectionUtils.application = app.application
	}

	void testSetConfigProperty() {
		def foo = application.config.grails.plugin.springsecurity.foo
//		assert foo instanceof ConfigObject
		assert 0 == foo.size()

		ReflectionUtils.setConfigProperty 'foo', 'bar'
		assert 'bar' == application.config.grails.plugin.springsecurity.foo
	}

	void testGetConfigProperty() {
		def d = ReflectionUtils.getConfigProperty('a.b.c')
//		assert d instanceof ConfigObject
		assert 0 == d.size()

		ReflectionUtils.setConfigProperty 'a.b.c', 'd'
		assert 'd' == ReflectionUtils.getConfigProperty('a.b.c')
		assert 'd' == application.config.grails.plugin.springsecurity.a.b.c
	}

	void testGetRoleAuthority() {
		String authorityName = 'ROLE_FOO'
		def role = [authority: authorityName]
		assert authorityName == ReflectionUtils.getRoleAuthority(role)
	}

	void testGetRequestmapUrl() {
		String url = '/admin/**'
		def requestmap = [url: url]
		assert url == ReflectionUtils.getRequestmapUrl(requestmap)
	}

	void testGetRequestmapConfigAttribute() {
		String configAttribute = 'ROLE_ADMIN'
		def requestmap = [configAttribute: configAttribute]
		assert configAttribute == ReflectionUtils.getRequestmapConfigAttribute(requestmap)
	}

	void testAsList() {
		def list = ReflectionUtils.asList(null)
		assert list instanceof List
		assert !list

		list = ReflectionUtils.asList([1,2,3])
		assert list instanceof List
		assert 3 == list.size()

		String[] strings = ['a', 'b']
		list = ReflectionUtils.asList(strings)
		assert list instanceof List
		assert 2 == list.size()
	}

	void testSplitMap() {
		def map = [a: 'b', c: ['d', 'e']]
		List<InterceptedUrl> split = ReflectionUtils.splitMap(map)
		assert 2 == split.size()

/*		for (InterceptedUrl iu in split) {
			assert key instanceof String
			assert value instanceof List
		}
		assert ['b'] == split.a
		assert ['d', 'e'] == split.c
*/	}

	void testGetGrailsServerURLWhenSet() {
		setAndCheckGrailsServerURL 'http://somewhere.org'
	}

	void testGetGrailsServerURLWhenNotSet() {
		setAndCheckGrailsServerURL null
	}

	protected void setAndCheckGrailsServerURL(String url) {
		ReflectionUtils.application.config.grails.serverURL = url

		assert ReflectionUtils.getGrailsServerURL() == url
	}

	@Override
	protected void tearDown() {
		super.tearDown()
		SpringSecurityUtils.resetSecurityConfig()
		ReflectionUtils.application = null
	}
}