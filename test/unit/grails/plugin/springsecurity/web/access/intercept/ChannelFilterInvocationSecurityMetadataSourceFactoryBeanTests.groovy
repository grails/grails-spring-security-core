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
package grails.plugin.springsecurity.web.access.intercept

import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource
import org.springframework.security.web.util.matcher.AntPathRequestMatcher

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class ChannelFilterInvocationSecurityMetadataSourceFactoryBeanTests extends GroovyTestCase {

	private ChannelFilterInvocationSecurityMetadataSourceFactoryBean factory = new ChannelFilterInvocationSecurityMetadataSourceFactoryBean()

	void testGetObjectType() {
		assert DefaultFilterInvocationSecurityMetadataSource.is(factory.objectType)
	}

	void testIsSingleton() {
		assert factory.singleton
	}

	void testAfterPropertiesSet() {
		shouldFail(IllegalArgumentException) {
			factory.afterPropertiesSet()
		}

		shouldFail(IllegalArgumentException) {
			factory.afterPropertiesSet()
		}

		factory.definition = ['/foo1/**': 'secure_only']
		shouldFail(IllegalArgumentException) {
			factory.afterPropertiesSet()
		}

		factory.definition = ['/foo1/**': 'REQUIRES_SECURE_CHANNEL']
		factory.afterPropertiesSet()
	}

	void testGetObject() {
		factory.definition = ['/foo1/**': 'REQUIRES_SECURE_CHANNEL',
		                      '/foo2/**': 'REQUIRES_INSECURE_CHANNEL',
		                      '/foo3/**': 'ANY_CHANNEL']
		factory.afterPropertiesSet()

		def object = factory.object
		assert object instanceof DefaultFilterInvocationSecurityMetadataSource
		def map = object.@requestMap
		assert 'REQUIRES_SECURE_CHANNEL'   == map[new AntPathRequestMatcher('/foo1/**')].attribute[0]
		assert 'REQUIRES_INSECURE_CHANNEL' == map[new AntPathRequestMatcher('/foo2/**')].attribute[0]
		assert 'ANY_CHANNEL'               == map[new AntPathRequestMatcher('/foo3/**')].attribute[0]
	}
}
