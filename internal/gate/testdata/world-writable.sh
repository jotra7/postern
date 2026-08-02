#!/bin/sh
# Contents are irrelevant: this file exists to be chmodded 0777 by a test, so
# CheckScriptPath has a real file to refuse. Git records only 0755 or 0644, so
# the mode under test is applied when the test copies this into place.
set -eu
exit 0
