/* Copyright 2015 the original author or authors.
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

import grails.plugin.springsecurity.web.access.intercept.TestApplication

import grails.core.GrailsApplication
import org.springframework.security.access.vote.AuthenticatedVoter
import org.springframework.security.access.vote.RoleVoter
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler
import org.springframework.web.context.WebApplicationContext

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
class TestUtils {

	static createTestApplication() {

		def application = new TestApplication()

		def beans = [
			(GrailsApplication.APPLICATION_ID): application,
			webExpressionHandler: new DefaultWebSecurityExpressionHandler(),
			roleVoter: new RoleVoter(),
			authenticatedVoter: new AuthenticatedVoter()]

		def ctx = [getBean: { String name, Class<?> c = null -> beans[name] },
					  containsBean: { String name -> beans.containsKey(name) } ] as WebApplicationContext

		application.mainContext = ctx

		[application: application, beans: beans, ctx: ctx]
	}
}
