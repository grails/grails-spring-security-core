import grails.util.BuildSettings
import grails.util.Environment

import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.LoggingEvent
import org.slf4j.LoggerFactory

String defaultPattern = '%-65(%.-2level %date{HH:mm:ss.SSS} %logger{32}) - %message%n'

class ExceptionFilteringConsoleAppender extends ConsoleAppender<LoggingEvent> {

	protected void writeOut(LoggingEvent event) throws IOException {
		if (event.throwableProxy) {
			if (event.level == DEBUG || event.loggerName == 'org.springframework.boot.context.web.ErrorPageFilter') {
				event = new LoggingEvent(Logger.FQCN, LoggerFactory.getLogger(event.loggerName) as Logger,
						event.level, event.message, null, event.argumentArray)
			}
		}

		super.writeOut event
	}
}

appender('STDOUT', ExceptionFilteringConsoleAppender) {
	encoder(PatternLayoutEncoder) {
		pattern = defaultPattern
	}
}

// logger 'grails.plugin.springsecurity', TRACE
// logger 'org.springframework.security', DEBUG
// logger 'org.hibernate.SQL', DEBUG
// logger 'org.hibernate.type.descriptor.sql.BasicBinder', TRACE

root ERROR, ['STDOUT']

File targetDir = BuildSettings.TARGET_DIR
if (Environment.developmentMode && targetDir) {

	appender('FULL_STACKTRACE', FileAppender) {
		file = "$targetDir/stacktrace.log"
		append = true
		encoder(PatternLayoutEncoder) {
			pattern = defaultPattern
		}
	}

	logger 'StackTrace', ERROR, ['FULL_STACKTRACE'], false
}
