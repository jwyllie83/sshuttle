# Edit this file with network prefixes that should be loaded through the SSH
# tunnel.
export PREFIX_LOCATION=/etc/sshuttle/prefixes.conf

# Routing table; defaults to 100
export ROUTE_TABLE=100

# fwmark; defaults to 1
export FWMARK=1

# SSH tunnel configuration file
export SSHUTTLE_TUNNEL_FILE=/etc/sshuttle/tunnel.conf

# File containing the tunnel proxy name / host / whatever
export TUNNEL_PROXY="/etc/sshuttle/tunnel.conf"

# Any other commands needed to run before or after loading the SSH tunnel.
# This is where you can put any of your hacks to set up tunnels-in-tunnels,
# etc.  Scripts in this directory are executed in order.
export MISC_START_DIR=/etc/sshuttle/pre-start.d
export MISC_STOP_DIR=/etc/sshuttle/post-stop.d

# Make sure we have created the routes
sudo ip rule add fwmark ${FWMARK} lookup ${ROUTE_TABLE}
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

sudo /usr/bin/sshuttle --dns --method=tproxy --listen 0.0.0.0 --remote sshuttle_tunnel -s /etc/sshuttle/prefixes.conf -e "ssh -F ${TUNNEL_PROXY}" &
