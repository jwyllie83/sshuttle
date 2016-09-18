#!/bin/bash
# Log what's going on
# Intuitively, I'm thinking this needs some kind of decorator, where I can
# write a Bash function like echo that will redirect to some static location.
# I can't think of an obvious way to do that for like three commands that
# doesn't involve shell expansion hell, so I'm not going to bother.
export LOGFILE=/tmp/sshuttle/sshuttle-post-stop.sh.logs
mkdir -p "$(dirname "${LOGFILE}")"

: > "${LOGFILE}"

if [ -f "${PREFIX_LOCATION}" ]; then
	cat "${PREFIX_LOCATION}" | while read ROUTE; do

		# Skip comments
		if [ -n "$(echo ${ROUTE} | egrep "^[ 	]*#")" ]; then
			continue
		fi

		# Skip empty lines
		if [ -z "${ROUTE}" ]; then
			continue
		fi

		echo "Deleting route: ${ROUTE}"
		ip route del local ${ROUTE} dev lo table ${ROUTE_TABLE} >> "${LOGFILE}" 2>&1
	done
fi

ip rule del fwmark ${FWMARK} >> "${LOGFILE}" 2>&1

for RUNFILE in ${MISC_STOP_DIR}/*; do
	echo "Executing ${RUNFILE}"
	/bin/sh -c "${RUNFILE}" >> "${LOGFILE}" 2>&1
done
