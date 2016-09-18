#!/bin/bash
# Log what's going on
# Intuitively, I'm thinking this needs some kind of decorator, where I can
# write a Bash function like echo that will redirect to some static location.
# I can't think of an obvious way to do that for like three commands that
# doesn't involve shell expansion hell, so I'm not going to bother.
export LOGFILE=/tmp/sshuttle/sshuttle-pre-start.sh.logs
mkdir -p "$(dirname "${LOGFILE}")"

: > "${LOGFILE}"

# Make sure we have created the routes
ip rule add fwmark ${FWMARK} lookup ${ROUTE_TABLE} >> "${LOGFILE}" 2>&1
echo "Starting sshuttle..." >> "${LOGFILE}" 2>&1

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

		echo "Adding route: ${ROUTE}" >> "${LOGFILE}" 2>&1
		ip route add local ${ROUTE} dev lo table ${ROUTE_TABLE} >> "${LOGFILE}" 2>&1
	done
fi

for RUNFILE in ${MISC_START_DIR}/*; do
	echo "Executing ${RUNFILE}" >> "${LOGFILE}" 2>&1
	/bin/sh -c "${RUNFILE}" >> "${LOGFILE}" 2>&1
done
