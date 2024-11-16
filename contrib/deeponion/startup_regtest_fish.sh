#!/usr/bin/env fish

## Short script to startup some local nodes with DeepOniond, all running on regtest.
## Makes it easier to test things out, by hand.

## Should be called by source since it sets aliases
## First load this file up.
##   source contrib/deeponion/startup_regtest_fish.sh
## Start up the nodeset
##   start_ln 3
## Let's connect the nodes. The `connect a b` command connects node a to b.
##   connect 1 2
## When you're finished, clean up or stop
##   stop_ln
##   destroy_ln # clean up the lightning directories

# Set up the Lightning and DeepOnion environment
if test -z "$LIGHTNING_BIN" -a -x "cli/lightning-cli" -a -x "lightningd/lightningd"
    set -g LIGHTNING_BIN (pwd)
end

if test -z "$LIGHTNING_BIN"
    if not type -q lightning-cli
        echo "lightning-cli: not found"
        return 1
    end
    if not type -q lightningd
        echo "lightningd: not found"
        return 1
    end
    set -g LCLI "lightning-cli"
    set -g LIGHTNINGD "lightningd"
else
    set -g LCLI "$LIGHTNING_BIN/cli/lightning-cli"
    set -g LIGHTNINGD "$LIGHTNING_BIN/lightningd/lightningd"
end

if test -z "$LIGHTNING_DIR"
    set -g LIGHTNING_DIR "/tmp"
end

if test -z "$DEEPONION_DIR"
    if test -d "$HOME/snap/deeponion/common/.DeepOnion"
        set -g DEEPONION_DIR "$HOME/snap/deeponion/common/.DeepOnion"
    else if test -d "$HOME/.DeepOnion"
        set -g DEEPONION_DIR "$HOME/.DeepOnion"
    else if test -d "$HOME/Library/Application Support/DeepOnion/"
        set -g DEEPONION_DIR "$HOME/Library/Application Support/DeepOnion/"
    else
        echo "\$DEEPONION_DIR not set to a .DeepOnion dir?"
        return 1
    end
end

if test -z "$DEEPONION_BIN"
    if not type -q DeepOnion-cli
        echo "DeepOnion-cli: not found"
        return 1
    end
    if not type -q DeepOniond
        echo "DeepOniond: not found"
        return 1
    end
    set -g DOCLI "DeepOnion-cli"
    set -g DEEPONIOND "DeepOniond"
else
    set -g DOCLI "$DEEPONION_BIN/DeepOnion-cli"
    set -g DEEPONIOND "$DEEPONION_BIN/DeepOniond"
end

echo "lightning-cli is $LCLI"
echo "lightningd is $LIGHTNINGD"
echo "lightning-dir is $LIGHTNING_DIR"
echo "DeepOnion-cli is $DOCLI"
echo "DeepOniond is $DEEPONIOND"
echo "DeepOnion-dir is $DEEPONION_DIR"

function wait_for_lightningd
    if test -n "$argv[1]"
        set node_count $argv[1]
    else
        set node_count 2
    end
    for i in (seq 5)
        if $LCLI --lightning-dir="$LIGHTNING_DIR/l$node_count" getinfo > /dev/null 2>&1
            break
        else
            sleep 1
        end
    end
end

function start_nodes
    if test -n "$argv[1]"
        set node_count $argv[1]
    else
        set node_count 2
    end
    if test "$node_count" -gt 100
        set node_count 100
    end
    if test -n "$argv[2]"
        set network $argv[2]
    else
        set network "regtest"
    end

    if type -q eatmydata
        set EATMYDATA "eatmydata"
    else
        set EATMYDATA ""
    end

    set -g LN_NODES $node_count

    for i in (seq "$node_count")
        set socket (math "7070 + $i * 101")
        mkdir -p "$LIGHTNING_DIR/l$i"

        # Node config
        echo "network=$network" > "$LIGHTNING_DIR/l$i/config"
        echo "log-level=debug" >> "$LIGHTNING_DIR/l$i/config"
        echo "log-file=$LIGHTNING_DIR/l$i/log" >> "$LIGHTNING_DIR/l$i/config"
        echo "addr=localhost:$socket" >> "$LIGHTNING_DIR/l$i/config"
        echo "allow-deprecated-apis=false" >> "$LIGHTNING_DIR/l$i/config"
        echo "developer" >> "$LIGHTNING_DIR/l$i/config"
        echo "dev-fast-gossip" >> "$LIGHTNING_DIR/l$i/config"
        echo "dev-deeponiond-poll=5" >> "$LIGHTNING_DIR/l$i/config"

        # Start the lightning nodes
        if not test -f "$LIGHTNING_DIR/l$i/lightningd-$network.pid"
            if test -n "$EATMYDATA"
                $EATMYDATA "$LIGHTNINGD" "--network=$network" "--lightning-dir=$LIGHTNING_DIR/l$i" "--deeponion-datadir=$DEEPONION_DIR" "--database-upgrade=true" &
            else
                "$LIGHTNINGD" "--network=$network" "--lightning-dir=$LIGHTNING_DIR/l$i" "--deeponion-datadir=$DEEPONION_DIR" "--database-upgrade=true" &
            end
        end

        # Define CLI and log functions for fish shell
        functions -e "l$i-cli" > /dev/null 2>&1
        functions -e "l$i-log" > /dev/null 2>&1
        function "l$i-cli"
            $LCLI --lightning-dir=$LIGHTNING_DIR/l$i $argv
        end
        function "l$i-log"
            less $LIGHTNING_DIR/l$i/log
        end
    end
end

function start_ln
    # Start DeepOniond in the background
    if not test -f "$DEEPONION_DIR/regtest/DeepOniond.pid"
        "$DEEPONIOND" -datadir="$DEEPONION_DIR" -regtest -txindex -fallbackfee=0.00000253 -daemon
    end

    # Wait for DeepOniond to start
    while not "$DOCLI" -datadir="$DEEPONION_DIR" -regtest ping > /dev/null 2>&1
        echo "awaiting DeepOniond..."
        sleep 1
    end

    if test -n "$argv[1]"
        set node_count $argv[1]
    else
        set node_count 2
    end
    start_nodes $node_count "regtest"
end

function stop_ln
    for i in (seq $LN_NODES)
        if test -f "$LIGHTNING_DIR/l$i/lightningd-regtest.pid"
            kill (cat "$LIGHTNING_DIR/l$i/lightningd-regtest.pid")
            rm "$LIGHTNING_DIR/l$i/lightningd-regtest.pid"
            functions -e "l$i-cli"
            functions -e "l$i-log"
        end
    end

    if test -f "$DEEPONION_DIR/regtest/DeepOniond.pid"
        kill (cat "$DEEPONION_DIR/regtest/DeepOniond.pid")
        rm "$DEEPONION_DIR/regtest/DeepOniond.pid"
    end

    set -e LN_NODES
end

function destroy_ln
    if test -e "$LIGHTNING_DIR"/l[0-9]*
        rm -rf "$LIGHTNING_DIR"/l[0-9]*
    end
end

function connect
    if test -z "$argv[1]" -o -z "$argv[2]"
        echo "usage: connect 1 2"
        return 1
    end

    # Collect the ID and address information into variables
    set node_info ($LCLI --lightning-dir="$LIGHTNING_DIR/l$argv[2]" -F getinfo)
    set ID (echo "$node_info" | grep '^id=' | cut -d= -f2)
    set ADDR (echo "$node_info" | grep '^binding\[0\]\.address=' | cut -d= -f2)
    set PORT (echo "$node_info" | grep '^binding\[0\]\.port=' | cut -d= -f2)
    set to "$ID@$ADDR:$PORT"

    $LCLI --lightning-dir="$LIGHTNING_DIR/l$argv[1]" connect "$to"
end

# Output helpful commands
echo "Useful commands:"
echo "  start_ln 3: start three nodes, l1, l2, l3"
echo "  connect 1 2: connect l1 and l2"
echo "  stop_ln: shutdown"
echo "  destroy_ln: remove ln directories"
