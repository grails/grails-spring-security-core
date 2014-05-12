/* Copyright 2006-2012 SpringSource.
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
package org.codehaus.groovy.grails.plugins.springsecurity

import grails.util.Holders as CH

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class ReflectionUtilsTests extends GroovyTestCase {

	private final application = new FakeApplication()

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#setUp()
	 */
	@Override
	protected void setUp() {
		super.setUp()
		ReflectionUtils.application = application
	}

	void testSetConfigProperty() {
		def foo = application.config.grails.plugins.springsecurity.foo
		assertTrue foo instanceof ConfigObject
		assertEquals 0, foo.size()

		ReflectionUtils.setConfigProperty 'foo', 'bar'
		assertEquals 'bar', application.config.grails.plugins.springsecurity.foo
	}

	void testGetConfigProperty() {
		def d = ReflectionUtils.getConfigProperty('a.b.c')
		assertTrue d instanceof ConfigObject
		assertEquals 0, d.size()

		ReflectionUtils.setConfigProperty 'a.b.c', 'd'
		assertEquals 'd', ReflectionUtils.getConfigProperty('a.b.c')
		assertEquals 'd', application.config.grails.plugins.springsecurity.a.b.c
	}

	void testGetRoleAuthority() {
		String authorityName = 'ROLE_FOO'
		def role = [authority: authorityName]
		assertEquals authorityName, ReflectionUtils.getRoleAuthority(role)
	}

	void testGetRequestmapUrl() {
		String url = '/admin/**'
		def requestmap = [url: url]
		assertEquals url, ReflectionUtils.getRequestmapUrl(requestmap)
	}

	void testGetRequestmapConfigAttribute() {
		String configAttribute = 'ROLE_ADMIN'
		def requestmap = [configAttribute: configAttribute]
		assertEquals configAttribute, ReflectionUtils.getRequestmapConfigAttribute(requestmap)
	}

	void testAsList() {
		def list = ReflectionUtils.asList(null)
		assertTrue list instanceof List
		assertEquals 0, list.size()

		list = ReflectionUtils.asList([1,2,3])
		assertTrue list instanceof List
		assertEquals 3, list.size()

		String[] strings = ['a', 'b']
		list = ReflectionUtils.asList(strings)
		assertTrue list instanceof List
		assertEquals 2, list.size()
	}

	void testSplitMap() {
		def map = [a: 'b', c: ['d', 'e']]
		def split = ReflectionUtils.splitMap(map)
		assertEquals 2, split.size()
		split.each { key, value ->
			assertTrue key instanceof String
			assertTrue value instanceof List
		}
		assertEquals(['b'], split.a)
		assertEquals(['d', 'e'], split.c)
	}

	/**
	 * {@inheritDoc}
	 * @see junit.framework.TestCase#tearDown()
	 */
	@Override
	protected void tearDown() {
		super.tearDown()
		SpringSecurityUtils.resetSecurityConfig()
		ReflectionUtils.application = null
		CH.config = null
	}
}
