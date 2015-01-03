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
package grails.plugin.springsecurity.web.access;

import javax.servlet.ServletException;

import org.springframework.security.web.util.ThrowableAnalyzer;
import org.springframework.security.web.util.ThrowableCauseExtractor;

/**
 * Copy of org.springframework.security.web.access.ExceptionTranslationFilter.DefaultThrowableAnalyzer which is private.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class DefaultThrowableAnalyzer extends ThrowableAnalyzer {

	@Override
	protected void initExtractorMap() {
		super.initExtractorMap();

		registerExtractor(ServletException.class, new ThrowableCauseExtractor() {
			public Throwable extractCause(Throwable throwable) {
				ThrowableAnalyzer.verifyThrowableHierarchy(throwable, ServletException.class);
				return ((ServletException)throwable).getRootCause();
			}
		});
	}
}
