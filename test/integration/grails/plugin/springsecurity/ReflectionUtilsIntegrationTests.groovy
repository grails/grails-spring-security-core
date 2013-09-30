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
package grails.plugin.springsecurity

import test.TestRequestmap

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class ReflectionUtilsIntegrationTests extends GroovyTestCase {

	void testLoadAllRequestmaps() {
		assertEquals 0, ReflectionUtils.loadAllRequestmaps().size()

		10.times {
			new TestRequestmap(urlPattern: "/url$it", rolePattern: "ROLE_$it").save(flush: true)
		}

		assertEquals 10, ReflectionUtils.loadAllRequestmaps().size()
	}
}
