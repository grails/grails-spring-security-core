/* Copyright 2006-2014 SpringSource.
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

import com.test.ScreamingBratLogoutHandler
import grails.plugin.springsecurity.web.authentication.logout.MutableLogoutFilter
import grails.test.mixin.TestMixin
import grails.test.mixin.integration.IntegrationTestMixin
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices

import static org.junit.Assert.assertEquals

/**
 * @author <a href='mailto:george@georgemcintosh.com'>George McIntosh</a>
 */
@TestMixin(IntegrationTestMixin)
class AdditionalLogoutFiltersConfiguredTests {

    def grailsApplication

    void testAllHandlersExist() {

        def expected = [ScreamingBratLogoutHandler, SecurityContextLogoutHandler, TokenBasedRememberMeServices].sort()

        def ctx = grailsApplication.mainContext
        MutableLogoutFilter logoutFilter = ctx.logoutFilter
        assertEquals 3, logoutFilter.handlers.size()

        def handlerClasses = logoutFilter.handlers.collect { it.class }.sort()

        assertEquals(expected, handlerClasses)

    }


}
