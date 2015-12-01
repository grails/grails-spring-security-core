/* Copyright 2013-2015 the original author or authors.
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
package grails.plugin.springsecurity.web.authentication.preauth.x509;

import groovy.lang.Closure;

import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;

/**
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class ClosureX509PrincipalExtractor implements X509PrincipalExtractor {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	protected Logger log = LoggerFactory.getLogger(getClass());

	protected Closure<?> closure;

	public Object extractPrincipal(X509Certificate clientCert) {
		String subjectDN = clientCert.getSubjectDN().getName();

		log.debug("Subject DN is '{}'", subjectDN);

		Object username = closure.call(subjectDN);

		if (username == null) {
			throw new BadCredentialsException(messages.getMessage("SubjectDnX509PrincipalExtractor.noMatching",
					new Object[] {subjectDN}, "No matching pattern was found in subject DN: {}"));
		}

		log.debug("Extracted Principal name is '{}'", username);

		return username;
	}

	/**
	 * Dependency injection for the closure to use to extract the username.
	 * @param closure the closure
	 */
	public void setClosure(Closure<?> closure) {
		this.closure = closure;
	}

	/**
	 * Dependency injection for the message source.
	 * @param messageSource the message source
	 */
	public void setMessageSource(MessageSource messageSource) {
		messages = new MessageSourceAccessor(messageSource);
	}
}
