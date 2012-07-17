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

import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
import org.springframework.security.web.util.AntUrlPathMatcher

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class ChannelFilterInvocationSecurityMetadataSourceFactoryBeanTests extends GroovyTestCase {

	private _factory = new ChannelFilterInvocationSecurityMetadataSourceFactoryBean()

	void testGetObjectType() {
		assertSame DefaultFilterInvocationSecurityMetadataSource, _factory.objectType
	}

	void testIsSingleton() {
		assertTrue _factory.singleton
	}

	void testAfterPropertiesSet() {
		shouldFail(IllegalArgumentException) {
			_factory.afterPropertiesSet()
		}

		_factory.urlMatcher = new AntUrlPathMatcher()
		shouldFail(IllegalArgumentException) {
			_factory.afterPropertiesSet()
		}

		_factory.definition = ['/foo1/**': 'secure_only']
		shouldFail(IllegalArgumentException) {
			_factory.afterPropertiesSet()
		}

		_factory.definition = ['/foo1/**': 'REQUIRES_SECURE_CHANNEL']
		_factory.afterPropertiesSet()
	}

	void testGetObject() {
		_factory.urlMatcher = new AntUrlPathMatcher()
		_factory.definition = ['/foo1/**': 'REQUIRES_SECURE_CHANNEL',
		                       '/foo2/**': 'REQUIRES_INSECURE_CHANNEL',
		                       '/foo3/**': 'ANY_CHANNEL']
		_factory.afterPropertiesSet()

		def object = _factory.object
		assertTrue object instanceof DefaultFilterInvocationSecurityMetadataSource
		def map = object.@httpMethodMap
		assertEquals 'REQUIRES_SECURE_CHANNEL',   map.get(null).get('/foo1/**').attribute[0]
		assertEquals 'REQUIRES_INSECURE_CHANNEL', map.get(null).get('/foo2/**').attribute[0]
		assertEquals 'ANY_CHANNEL',               map.get(null).get('/foo3/**').attribute[0]
	}
}
