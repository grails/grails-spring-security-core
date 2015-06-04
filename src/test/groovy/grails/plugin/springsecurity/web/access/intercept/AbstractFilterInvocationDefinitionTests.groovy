/* Copyright 2013-2015 SpringSource.
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

import grails.plugin.springsecurity.ReflectionUtils
import grails.plugin.springsecurity.TestUtils

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
abstract class AbstractFilterInvocationDefinitionTests extends GroovyTestCase {

	protected TestApplication application
	protected ctx
	protected Map beans

	protected void setUp() {
		super.setUp()
		def app = TestUtils.createTestApplication()
		application = ReflectionUtils.application = app.application
		beans = app.beans
		ctx = app.ctx
	}

	protected void tearDown() {
		super.tearDown()
		ReflectionUtils.application = null
	}
}
