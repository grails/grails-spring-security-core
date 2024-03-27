package grails.plugin.springsecurity

class SoftwareVersion implements Comparable<SoftwareVersion> {

    int major
    int minor
    int patch

    Snapshot snapshot
    String versionText

    static SoftwareVersion build(String versionString) {

        String[] parts = versionString.split('\\.')
        SoftwareVersion version = null

        if (parts.length >= 3) {

            version = new SoftwareVersion()
            version.versionText = versionString
            version.major = parts[0].toInteger()
            version.minor = parts[1].toInteger()
            def patchParts = parts[2].split('-')
            version.patch = patchParts[0].toInteger()

            if (patchParts.length > 1) {
                version.snapshot = new Snapshot(patchParts[1])
            } else if (parts[2].contains('-')) {
                String[] subparts = parts[2].split("-")
                version.patch = subparts.first() as int
                version.snapshot = new Snapshot(subparts[1..-1].join("-"))
                return version
            }
        }
        version
    }

    String getStableVersion() {
        if (this.isSnapshot()) {
            return "${this.major}.${this.minor}.${this.patch - 1}"
        } else {
            return this.versionText
        }
    }

    String getSnapshotVersion() {
        if (this.isSnapshot()) {
            return this.versionText
        } else {
            return "${this.major}.${this.minor}.${this.patch + 1}"
        }
    }

    boolean isSnapshot() {
        snapshot != null
    }

    @Override
    int compareTo(SoftwareVersion o) {
        int majorCompare = this.major <=> o.major
        if (majorCompare != 0) {
            return majorCompare
        }

        int minorCompare = this.minor <=> o.minor
        if (minorCompare != 0) {
            return minorCompare
        }

        int patchCompare = this.patch <=> o.patch
        if (patchCompare != 0) {
            return patchCompare
        }

        if (this.isSnapshot() && !o.isSnapshot()) {
            return -1
        } else if (!this.isSnapshot() && o.isSnapshot()) {
            return 1
        } else if (this.isSnapshot() && o.isSnapshot()) {
            return this.getSnapshot() <=> o.getSnapshot()
        } else {
            return 0
        }
    }

    @Override
    String toString() {
        return "SoftwareVersion{" +
                "major=" + major +
                ", minor=" + minor +
                ", patch=" + patch +
                ", snapshot=" + snapshot +
                ", versionText='" + versionText + '\'' +
                '}';
    }
}
