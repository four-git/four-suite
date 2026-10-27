#!/bin/sh
# Validate the Docker lifecycle; never start the retired native scanner units.
set -eu
cd /opt/four-security
python3 -m unittest discover -s tests -v
systemd-analyze verify /etc/systemd/system/four-security.service /etc/systemd/system/four-security-publish.service /etc/systemd/system/four-security-publish.timer
python3 suite doctor
