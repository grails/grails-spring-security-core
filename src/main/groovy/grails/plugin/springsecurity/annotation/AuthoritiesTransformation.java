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
package grails.plugin.springsecurity.annotation;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.codehaus.groovy.ast.ASTNode;
import org.codehaus.groovy.ast.AnnotatedNode;
import org.codehaus.groovy.ast.AnnotationNode;
import org.codehaus.groovy.ast.ClassNode;
import org.codehaus.groovy.ast.expr.ConstantExpression;
import org.codehaus.groovy.ast.expr.Expression;
import org.codehaus.groovy.ast.expr.ListExpression;
import org.codehaus.groovy.control.CompilePhase;
import org.codehaus.groovy.control.SourceUnit;
import org.codehaus.groovy.control.messages.SyntaxErrorMessage;
import org.codehaus.groovy.syntax.SyntaxException;
import org.codehaus.groovy.transform.ASTTransformation;
import org.codehaus.groovy.transform.GroovyASTTransformation;
import org.springframework.util.StringUtils;

/**
 * See http://burtbeckwith.com/blog/?p=1398 for the motivation for this.
 *
 * @author <a href='mailto:burt@burtbeckwith.com'>Burt Beckwith</a>
 */
@GroovyASTTransformation(phase=CompilePhase.CANONICALIZATION)
public class AuthoritiesTransformation implements ASTTransformation {

	protected static final ClassNode SECURED = new ClassNode(Secured.class);

	public void visit(final ASTNode[] astNodes, final SourceUnit sourceUnit) {
		ASTNode firstNode = astNodes[0];
		ASTNode secondNode = astNodes[1];
		try {
			if (!(firstNode instanceof AnnotationNode) || !(secondNode instanceof AnnotatedNode)) {
				throw new IllegalArgumentException("Internal error: wrong types: " + firstNode.getClass().getName() +
						" / " + secondNode.getClass().getName());
			}

			AnnotationNode rolesAnnotationNode = (AnnotationNode) firstNode;
			AnnotatedNode annotatedNode = (AnnotatedNode) secondNode;

			AnnotationNode secured = createAnnotation(rolesAnnotationNode, sourceUnit);
			if (secured != null) {
				annotatedNode.addAnnotation(secured);
			}
		}
		catch (Exception e) {
			reportError(e.getMessage(), sourceUnit, firstNode);
		}
	}

	protected AnnotationNode createAnnotation(final AnnotationNode rolesNode, final SourceUnit sourceUnit) throws IOException {
		Expression value = rolesNode.getMembers().get("value");
		if (!(value instanceof ConstantExpression)) {
			reportError("annotation @Authorities value isn't a ConstantExpression: " + value, sourceUnit, rolesNode);
			return null;
		}

		String fieldName = value.getText();
		String[] authorityNames = getAuthorityNames(fieldName, rolesNode, sourceUnit);
		if (authorityNames == null) {
			return null;
		}

		return buildAnnotationNode(authorityNames);
	}

	protected AnnotationNode buildAnnotationNode(String[] authorityNames) {
		AnnotationNode securedAnnotationNode = new AnnotationNode(SECURED);
		List<Expression> nameExpressions = new ArrayList<Expression>();
		for (String authorityName : authorityNames) {
			nameExpressions.add(new ConstantExpression(authorityName));
		}
		securedAnnotationNode.addMember("value", new ListExpression(nameExpressions));
		return securedAnnotationNode;
	}

	protected String[] getAuthorityNames(final String fieldName, final AnnotationNode rolesNode, final SourceUnit sourceUnit) throws IOException {

		Properties properties = new Properties();
		File propertyFile = new File("roles.properties");
		if (!propertyFile.exists()) {
			reportError("Property file roles.properties not found", sourceUnit, rolesNode);
			return null;
		}

		properties.load(new FileReader(propertyFile));

		Object value = properties.getProperty(fieldName);
		if (value == null) {
			reportError("No value for property '" + fieldName + "'", sourceUnit, rolesNode);
			return null;
		}

		List<String> names = new ArrayList<String>();
		for (String auth : StringUtils.commaDelimitedListToStringArray(value.toString())) {
			auth = auth.trim();
			if (auth.length() > 0) {
				names.add(auth);
			}
		}

		return names.toArray(new String[names.size()]);
	}

	protected void reportError(final String message, final SourceUnit sourceUnit, final ASTNode node) {
		SyntaxException se = new SyntaxException(message, node.getLineNumber(), node.getColumnNumber());
		sourceUnit.getErrorCollector().addErrorAndContinue(new SyntaxErrorMessage(se, sourceUnit));
	}
}
