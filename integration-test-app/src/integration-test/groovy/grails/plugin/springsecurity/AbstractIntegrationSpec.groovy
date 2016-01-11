/* Copyright 2014-2016 the original author or authors.
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

import org.springframework.transaction.annotation.Transactional

import grails.test.mixin.integration.Integration
import grails.transaction.Rollback
import spock.lang.Specification
import test.TestRole

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@Integration
@Rollback
@Transactional
abstract class AbstractIntegrationSpec extends Specification {

	def grailsApplication

	protected save(o, boolean flush = false) {
		o.save(failOnError: true, flush: flush)
	}

	protected void flush() {
		TestRole.withSession { session ->
			session.flush()
		}
	}

	protected void flushAndClear() {
		TestRole.withSession { session ->
			session.flush()
			session.clear()
		}
	}
}
