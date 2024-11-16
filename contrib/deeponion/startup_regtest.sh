#!/bin/sh

## Short script to startup some local nodes with
## DeepOniond, all running on regtest
## Makes it easier to test things out, by hand.

## Should be called by source since it sets aliases
##
##  First load this file up.
##
##  $ source contrib/deeponion/startup_regtest.sh
##
##  Start up the nodeset
##
##  $ start_ln 3
##
##  Let's connect the nodes. The `connect a b` command connects node a to b.
##
##  $ connect 1 2
##  {
##    "id" : "030b02fc3d043d2d47ae25a9306d98d2abb7fc9bee824e68b8ce75d6d8f09d5eb7"
##  }
##
##  When you're finished, clean up or stop
##
##  $ stop_ln
##  $ destroy_ln # clean up the lightning directories
##


# Do the Right Thing if we're currently in top of srcdir.
if [ -z "$LIGHTNING_BIN" ] && [ -x cli/lightning-cli ] && [ -x lightningd/lightningd ]; then
	LIGHTNING_BIN=$(pwd)
fi

if [ -z "$LIGHTNING_BIN" ]; then
	# Already installed maybe?  Prints
	if ! type lightning-cli >/dev/null 2>&1 ; then
		echo lightning-cli: not found
		return 1
	fi
	if ! type lightningd >/dev/null 2>&1 ; then
		echo lightningd: not found
		return 1
	fi
	LCLI=lightning-cli
	LIGHTNINGD=lightningd
else
	LCLI="$LIGHTNING_BIN"/cli/lightning-cli
	LIGHTNINGD="$LIGHTNING_BIN"/lightningd/lightningd
	# This mirrors "type" output above.
fi

if [ -z "$LIGHTNING_DIR" ]; then
    # Default is to use the /tmp directory
    LIGHTNING_DIR=/tmp
fi

if [ -z "$DEEPONION_DIR" ]; then
  if [ -d "$HOME/snap/deeponion/common/.DeepOnion" ]; then
		DEEPONION_DIR="$HOME/snap/deeponion/common/.DeepOnion"
	elif [ -d "$HOME/.DeepOnion" ]; then
		DEEPONION_DIR="$HOME/.DeepOnion"
	elif [ -d "$HOME/Library/Application Support/DeepOnion/" ]; then
		DEEPONION_DIR="$HOME/Library/Application Support/DeepOnion/"
	else
		echo "\$DEEPONION_DIR not set to a .DeepOnion dir?" >&2
		return
	fi
fi

# shellcheck disable=SC2153
if [ -z "$DEEPONION_BIN" ]; then
	# Already installed maybe?  Prints
	if ! type DeepOnion-cli >/dev/null 2>&1 ; then
		echo DeepOnion-cli: not found
		return 1
	fi
	if ! type DeepOniond >/dev/null 2>&1 ; then
		echo DeepOniond: not found
		return 1
	fi
	DOCLI=DeepOnion-cli
  DEEPONIOND=DeepOniond
else
    DOCLI="$DEEPONION_BIN"/DeepOnion-cli
    DEEPONIOND="$DEEPONION_BIN"/DeepOniond
fi


echo lightning-cli is "$LCLI"
echo lightningd is "$LIGHTNINGD"
echo lightning-dir is "$LIGHTNING_DIR"
export LCLI="$LCLI"
export LIGHTNINGD="$LIGHTNINGD"
export LIGHTNING_DIR="$LIGHTNING_DIR"

echo DeepOnion-cli is "$DOCLI"
echo DeepOniond is "$DEEPONIOND"
echo DeepOnion-dir is "$DEEPONION_DIR"
export DOCLI="$DOCLI"
export DEEPONIOND="$DEEPONIOND"
export DEEPONION_DIR="$DEEPONION_DIR"

wait_for_lightningd() {
	if [ -z "$1" ]; then
		node_count=2
	else
		node_count=$1
	fi
	for i in $(seq "5"); do
		if $LCLI --lightning-dir="$LIGHTNING_DIR"/l"$node_count" getinfo > /dev/null 2>&1; then
			break
		else
			sleep 1
		fi
	done
}

clnrest_status() {
	logfile="$1"
	active_str="plugin-clnrest.py: REST Server is starting"
	disabled_str="plugin-clnrest.py: Killing plugin: disabled itself"

	if grep -q "$active_str" "$logfile"; then
		echo "active"
	elif grep -q "$disabled_str" "$logfile"; then
		echo "disabled"
	else
		echo "waiting"
	fi
}

start_nodes() {
	if [ -z "$1" ]; then
		node_count=2
	else
		node_count=$1
	fi
	if [ "$node_count" -gt 100 ]; then
		node_count=100
	fi
	if [ -z "$2" ]; then
		network=regtest
	else
		network=$2
	fi
	# This supresses db syncs, for speed.
	if type eatmydata >/dev/null 2>&1; then
	    EATMYDATA=eatmydata
	else
	    EATMYDATA=
	fi

	LN_NODES=$node_count

	for i in $(seq "$node_count"); do
		socket=$(( 7070 + i * 101))
		mkdir -p "$LIGHTNING_DIR/l$i"
		# Node config
		cat <<- EOF > "$LIGHTNING_DIR/l$i/config"
		network=$network
		log-level=debug
		log-file=$LIGHTNING_DIR/l$i/log
		addr=localhost:$socket
		allow-deprecated-apis=false
		developer
		dev-fast-gossip
		dev-deeponiond-poll=5
		experimental-dual-fund
		experimental-splicing
		experimental-offers
		funder-policy=match
		funder-policy-mod=100
		funder-min-their-funding=10000
		funder-per-channel-max=100000
		funder-fuzz-percent=0
funder-lease-requests-only=false
		lease-fee-base-sat=2sat
		lease-fee-basis=50
		invoices-onchain-fallback
		EOF

		# If clnrest loads, add the port so it will run
		if [ -n "$ACTIVATE_CLNREST" ]; then
			echo "clnrest-port=$((3109+i))" >> "$LIGHTNING_DIR/l$i/config"
		fi

		# Start the lightning nodes
		test -f "$LIGHTNING_DIR/l$i/lightningd-$network.pid" || \
			$EATMYDATA "$LIGHTNINGD" "--network=$network" "--lightning-dir=$LIGHTNING_DIR/l$i" "--deeponion-datadir=$DEEPONION_DIR" "--database-upgrade=true" &
		# shellcheck disable=SC2139 disable=SC2086
		alias l$i-cli="$LCLI --lightning-dir=$LIGHTNING_DIR/l$i"
		# shellcheck disable=SC2139 disable=SC2086
		alias l$i-log="less $LIGHTNING_DIR/l$i/log"
	done

	if [ -z "$EATMYDATA" ]; then
	    echo "WARNING: eatmydata not found: install it for faster testing"
	fi
	# Give a hint.
	echo "Commands: "

	for i in $(seq "$node_count"); do
		echo "	l$i-cli, l$i-log,"
	done
}

start_ln() {
	# Start DeepOniond in the background
	test -f "$DEEPONION_DIR/regtest/DeepOniond.pid" || \
		"$DEEPONIOND" -datadir="$DEEPONION_DIR" -regtest -txindex -fallbackfee=0.00000253 -daemon

	# Wait for it to start.
	while ! "$DOCLI" -datadir="$DEEPONION_DIR" -regtest ping 2> /tmp/null; do echo "awaiting DeepOniond..." && sleep 1; done

	# Check if default wallet exists
	if ! "$DOCLI" -datadir="$DEEPONION_DIR" -regtest listwalletdir | jq -r '.wallets[] | .name' | grep -wqe 'default' ; then
		# wallet dir does not exist, create one
		echo "Making \"default\" DeepOniond wallet."
		"$DOCLI" -datadir="$DEEPONION_DIR" -regtest createwallet default >/dev/null 2>&1
	fi

	# Check if default wallet is loaded
	if ! "$DOCLI" -datadir="$DEEPONION_DIR" -regtest listwallets | jq -r '.[]' | grep -wqe 'default' ; then
		echo "Loading \"default\" DeepOniond wallet."
		"$DOCLI" -datadir="$DEEPONION_DIR" -regtest loadwallet default >/dev/null 2>&1
	fi

	# Kick it out of initialblockdownload if necessary
	if "$DOCLI" -datadir="$DEEPONION_DIR" -regtest getblockchaininfo | grep -q 'initialblockdownload.*true'; then
		"$DOCLI" -datadir="$DEEPONION_DIR" -regtest generatetoaddress 1 "$($DOCLI -datadir="$DEEPONION_DIR" -regtest getnewaddress)" > /dev/null
	fi

	alias bt-cli='"$DOCLI" -datadir="$DEEPONION_DIR" -regtest'

	if [ -z "$1" ]; then
		nodes=2
	else
		nodes="$1"
	fi
	# Are the clnrest dependencies installed?
	if timeout 2 python3 plugins/clnrest/clnrest.py > /dev/null 2>&1; then
		ACTIVATE_CLNREST=1
	fi
	start_nodes "$nodes" regtest
	echo "	do-cli, stop_ln, fund_nodes"

	wait_for_lightningd "$nodes"
	active_status=$(clnrest_status "$LIGHTNING_DIR/l1/log")
	if [ -n "$ACTIVATE_CLNREST" ] && [ "$active_status" = "active" ] ; then
		node_info regtest
	elif [ "$active_status" = "disabled" ]; then
		echo "clnrest is disabled. Try installing python developer dependencies"
		echo "with 'poetry install'"
	else
		echo "timed out parsing log $LIGHTNING_DIR/l1/log"
	fi
}

ensure_deeponiond_funds() {

	if [ -z "$ADDRESS" ]; then
		ADDRESS=$("$DOCLI" -datadir="$DEEPONION_DIR" -regtest "$WALLET" getnewaddress)
	fi

	balance=$("$DOCLI" -datadir="$DEEPONION_DIR" -regtest "$WALLET" getbalance)

	if [ 1 -eq "$(echo "$balance"'<1' | bc -l)" ]; then

		printf "%s" "Mining into address " "$ADDRESS""... "

		"$DOCLI" -datadir="$DEEPONION_DIR" -regtest generatetoaddress 100 "$ADDRESS" > /dev/null

		echo "done."
	fi
}

fund_nodes() {
	WALLET="default"
	NODES=""

	for var in "$@"; do
		case $var in
			-w=*|--wallet=*)
				WALLET="${var#*=}"
				;;
			*)
				NODES="${NODES:+${NODES} }${var}"
				;;
		esac
	done

	if [ -z "$NODES" ]; then
		NODES=$(seq "$node_count")
	fi

	WALLET="-rpcwallet=$WALLET"

	ADDRESS=$("$DOCLI" -datadir="$DEEPONION_DIR" -regtest "$WALLET" getnewaddress)

	ensure_deeponiond_funds

	echo "DeepOniond balance:" "$("$DOCLI" -datadir="$DEEPONION_DIR" -regtest "$WALLET" getbalance)"

	last_node=""

	echo "$NODES" | while read -r i; do

		if [ -z "$last_node" ]; then
			last_node=$i
			continue
		fi

		node1=$last_node
		node2=$i
		last_node=$i

		L2_NODE_ID=$("$LCLI" -F --lightning-dir="$LIGHTNING_DIR"/l"$node2" getinfo | sed -n 's/^id=\(.*\)/\1/p')
		L2_NODE_PORT=$("$LCLI" -F --lightning-dir="$LIGHTNING_DIR"/l"$node2" getinfo | sed -n 's/^binding\[0\].port=\(.*\)/\1/p')

		"$LCLI" -H --lightning-dir="$LIGHTNING_DIR"/l"$node1" connect "$L2_NODE_ID"@localhost:"$L2_NODE_PORT" > /dev/null

		L1_WALLET_ADDR=$($LCLI -F --lightning-dir=$LIGHTNING_DIR/l"$node1" newaddr | sed -n 's/^bech32=\(.*\)/\1/p')
		L2_WALLET_ADDR=$($LCLI -F --lightning-dir=$LIGHTNING_DIR/l"$node2" newaddr | sed -n 's/^bech32=\(.*\)/\1/p')

		ensure_deeponiond_funds

		"$DOCLI" -datadir="$DEEPONION_DIR" -regtest "$WALLET" sendtoaddress "$L1_WALLET_ADDR" 1 > /dev/null
		"$DOCLI" -datadir="$DEEPONION_DIR" -regtest "$WALLET" sendtoaddress "$L2_WALLET_ADDR" 1 > /dev/null

		"$DOCLI" -datadir="$DEEPONION_DIR" -regtest generatetoaddress 1 "$ADDRESS" > /dev/null

		printf "%s" "Waiting for lightning node funds... "

		while ! "$LCLI" -F --lightning-dir="$LIGHTNING_DIR"/l"$node1" listfunds | grep -q "outputs"
		do
			sleep 1
		done

		while ! "$LCLI" -F --lightning-dir="$LIGHTNING_DIR"/l"$node2" listfunds | grep -q "outputs"
		do
			sleep 1
		done

		echo "found."

		printf "%s" "Funding channel <-> node " "$node1" " to node " "$node2"". "

		"$LCLI" --lightning-dir="$LIGHTNING_DIR"/l"$node1" fundchannel "$L2_NODE_ID" 1000000 > /dev/null

		"$DOCLI" -datadir="$DEEPONION_DIR" -regtest generatetoaddress 6 "$ADDRESS" > /dev/null

		printf "%s" "Waiting for confirmation... "

		while ! "$LCLI" -F --lightning-dir=$LIGHTNING_DIR/l"$node1" listchannels | grep -q "channels"
		do
			sleep 1
		done

		echo "done."

	done
}

stop_nodes() {
	network=${1:-regtest}
	if [ -n "$LN_NODES" ]; then
		for i in $(seq "$LN_NODES"); do
			test ! -f "$LIGHTNING_DIR/l$i/lightningd-$network.pid" || \
				(kill "$(cat "$LIGHTNING_DIR/l$i/lightningd-$network.pid")"; \
				rm "$LIGHTNING_DIR/l$i/lightningd-$network.pid")
			unalias "l$i-cli"
			unalias "l$i-log"
		done
	fi
}

stop_ln() {
	stop_nodes "$@"
	test ! -f "$DEEPONION_DIR/regtest/DeepOniond.pid" || \
		(kill "$(cat "$DEEPONION_DIR/regtest/DeepOniond.pid")"; \
		rm "$DEEPONION_DIR/regtest/DeepOniond.pid")

	unset LN_NODES
	unalias do-cli
}

node_info() {
	network=${1:-regtest}
	if [ -n "$LN_NODES" ]; then
		echo "Node Info:"
		for i in $(seq "$LN_NODES"); do
			echo "	l$i rest: https://127.0.0.1:$((3109 + i))"\
			" rune: $($LCLI --lightning-dir="$LIGHTNING_DIR"/l"$i" createrune | jq .rune)"
		done
	fi
}

destroy_ln() {
	rm -rf $LIGHTNING_DIR/l[0-9]*
}

connect() {
	if [ -z "$1" ] || [ -z "$2" ]; then
		printf "usage: connect 1 2\n"
	else
		to=$("$LCLI" --lightning-dir="$LIGHTNING_DIR/l$2" -F getinfo | grep '^\(id\|binding\[0\]\.\(address\|port\)\)' | cut -d= -f2- | tr '\n' ' ' | (read -r ID ADDR PORT; echo "$ID@${ADDR}:$PORT"))
		"$LCLI" --lightning-dir="$LIGHTNING_DIR"/l"$1" connect "$to"
	fi
}

echo Useful commands:
echo "  start_ln 3: start three nodes, l1, l2, l3"
echo "  connect 1 2: connect l1 and l2"
echo "  fund_nodes: connect all nodes with channels, in a row"
echo "  stop_ln: shutdown"
echo "  destroy_ln: remove ln directories"
