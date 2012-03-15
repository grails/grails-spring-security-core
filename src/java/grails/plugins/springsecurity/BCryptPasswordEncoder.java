/* Copyright 2006-2012 the original author or authors.
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
package grails.plugins.springsecurity;

import org.codehaus.groovy.grails.plugins.springsecurity.ReflectionUtils;
import org.mindrot.jbcrypt.BCrypt;
import org.springframework.dao.DataAccessException;
import org.springframework.security.authentication.encoding.PasswordEncoder;

/**
 * Password encoder that utilizes the <a
 * href="http://www.mindrot.org/projects/jBCrypt/">jBcrypt</a> bcrypt
 * implementation. Ignores salt property preferences and accepts
 * grails.plugins.springsecurity.bcrypt.logrounds configuration for work factor.
 *
 * @author <a href='mailto:oliver@tynes.inf'>Oliver Tynes</a>
 */
public class BCryptPasswordEncoder implements PasswordEncoder {

	/**
	 * Encodes a password with salt provided from configured amount of logrounds
	 * in <code>grails.plugins.springsecurity.bcrypt.logrounds</code> in
	 * <code>Config.groovy</code>.
	 *
	 * @param rawPassword cleartext password
	 * @param ignoredSalt not used, bcrypt goes by logrounds
	 * @return hashed password and salt/logrounds
	 * @throws DataAccessException
	 */
	public String encodePassword(String rawPassword, Object ignoredSalt) throws DataAccessException {
		Integer logRounds = (Integer)ReflectionUtils.getConfigProperty("password.bcrypt.logrounds");
		return BCrypt.hashpw(rawPassword, BCrypt.gensalt(logRounds));
	}

	/**
	 * Checks a user provided password against one previously encoded.
	 *
	 * @param encodedPassword encoded password
	 * @param rawPassword password provided from login attempt
	 * @param ignoredSalt not used, bcrypt goes by logrounds
	 * @return true if passwords match
	 * @throws DataAccessException
	 */
	public boolean isPasswordValid(String encodedPassword, String rawPassword, Object ignoredSalt) throws DataAccessException {
		return BCrypt.checkpw(rawPassword, encodedPassword);
	}
}
