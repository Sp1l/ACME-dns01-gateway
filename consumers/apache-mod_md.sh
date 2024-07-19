#!/bin/sh
# Script to configure for MDChallengeDns01.

### User configurable
# NOTE: Log-file must be writable for the Apache daemon user (www, apache, ...)
LOGFILE="/var/log/httpd/mod_md.log"
API_URI="https://acme.example.org:8000"
API_USER=""
API_PASSWD=""
DNS_DELAY=300
### END User configurable

action="$1"
domain="$2"
token="$3"

# Redirect all output to log-file
exec 2>&1
exec 1>>"${LOGFILE}"

timestamp_ms () {
    # Works with BSD and GNU date
    timestamp=$(date -I"ns")
    ms=${timestamp##*,} # nanosec + timezone
    ms=${ms%????????????}
    echo ${timestamp%,*}.${ms}
}

echo "$(timestamp_ms) $$ $*"

# Test for existence of ":" in $action
if [ "${action#*:}" != "${action}" ]; then
    # Used by challenge-setup:type:domain
    action2=${action#*:}  # Remove everything up to first :
    action=${action%%:*}  # Remove everything after first : (incl. :)
fi

if [ "${API_USER}" ]; then
    alias curl="/usr/local/bin/curl --no-progress-meter --fail-with-body -vk -u \"${API_USER}:${API_PASSWD}\""
else
    alias curl="/usr/local/bin/curl --no-progress-meter --fail-with-body -vk"
fi

case "$action" in
    # Commands from MDChallengeDns01
    "setup")
        curl "${API_URI}" -H "Content-Type: application/json" \
        -d "{\"argument\":\"${action}\",\"domain_name\":\"${domain}\",\"challenge_content\":\"${token}\"}" \
        RC=$?
        if [ $RC -eq 0 ]; then
            echo "$(timestamp_ms) sleeping ${DNS_DELAY} seconds"
            sleep ${DNS_DELAY}
        else
            echo "$(timestamp_ms) $$ error $RC from ${action}"
        fi
        ;;
    "teardown")
        curl "${API_URI}" -H "Content-Type: application/json" \
        -d "{\"argument\":\"${action}\",\"domain_name\":\"${domain}\",\"challenge_content\":\"${token}\"}" \
        RC=$?
        [ $RC -ge 1 ] && echo "$(timestamp_ms) $$ error $RC from ${action}"
        ;;
    # Events from MDMessageCmd
    "errored")
        ;;
    "expiring")
        ;;
    "renewed")
        ;;
    "installed")
        ;;
    "renewing")
        ;;
    "challenge-setup")
        ;;
    "ocsp-errored")
        ;;
    "ocsp-renewed")
        ;;
    *)
        ;;
esac

echo "$(timestamp_ms) $$ $* EXIT ${RC:=0}"

exit "${RC:=0}"
