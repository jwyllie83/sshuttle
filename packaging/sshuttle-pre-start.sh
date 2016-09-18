# Make sure we have created the routes
ip rule add fwmark ${FWMARK} lookup ${ROUTE_TABLE}
echo "Starting sshuttle..."

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

		echo "Adding route: ${ROUTE}"
		ip route add local ${ROUTE} dev lo table ${ROUTE_TABLE}
	done
fi

for RUNFILE in ${MISC_START_DIR}/*; do
	echo "Executing ${RUNFILE}"
	/bin/sh -c "${RUNFILE}" &
	sleep 1.5
done
