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
		ip route del local ${ROUTE} dev lo table ${ROUTE_TABLE}
	done
fi

ip rule del fwmark ${FWMARK}

for RUNFILE in ${MISC_STOP_DIR}/*; do
	echo "Executing ${RUNFILE}"
	/bin/sh -c "${RUNFILE}"
done
