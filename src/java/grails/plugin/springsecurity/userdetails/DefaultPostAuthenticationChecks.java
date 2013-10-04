/* Copyright 2011-2013 SpringSource.
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
package grails.plugin.springsecurity.userdetails;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;

/**
 * Copy of the private class in AbstractUserDetailsAuthenticationProvider
 * to make subclassing or replacement easier.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
public class DefaultPostAuthenticationChecks implements UserDetailsChecker {

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	protected final Logger log = LoggerFactory.getLogger(getClass());

	public void check(UserDetails user) {
		if (!user.isCredentialsNonExpired()) {
			log.debug("User account credentials have expired");

			throw new CredentialsExpiredException(messages.getMessage(
					"AbstractUserDetailsAuthenticationProvider.credentialsExpired",
					"User credentials have expired"));
		}
	}
}
