package grails.plugin.springsecurity

import spock.lang.Specification

class SoftwareVersionSpec extends Specification {

    // TODO: I'm not 100% sure how the SoftwareVersion class is supposed to work so this test is incomplete
    void "versions are parsed correctly"() {

        when: 'creating a SoftwareVersion'
            def version = SoftwareVersion.build(versionString)

        then: 'the version is parsed correctly'
            version.major == major
            version.minor == minor
            version.patch == patch
            version.isSnapshot() == isSnapshot
            version.stableVersion == stableVersion
            version.snapshotVersion == snapshotVersion

        where:
            versionString | major | minor | patch || isSnapshot | stableVersion | snapshotVersion
            '1.2.3'       | 1     | 2     | 3     || false      | '1.2.3'       | '1.2.4'
    }
}
