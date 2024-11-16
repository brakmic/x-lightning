#include "config.h"
#include <bitcoin/base58.h>
#include <ccan/array_size/array_size.h>
#include <ccan/cast/cast.h>
#include <ccan/io/io.h>
#include <ccan/pipecmd/pipecmd.h>
#include <ccan/read_write_all/read_write_all.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/memleak.h>
#include <errno.h>
#include <plugins/libplugin.h>

/* DeepOnion's web server has a default of 4 threads, with queue depth 16.
 * It will *fail* rather than queue beyond that, so we must not stress it!
 *
 * This is how many request for each priority level we have.
 */
#define DEEPONIOND_MAX_PARALLEL 4
#define RPC_TRANSACTION_ALREADY_IN_CHAIN -27

enum deeponiond_prio { BITCOIND_LOW_PRIO, BITCOIND_HIGH_PRIO };
#define DEEPONIOND_NUM_PRIO (BITCOIND_HIGH_PRIO + 1)

struct deeponiond {
	/* eg. "DeepOnion-cli" */
	char *cli;

	/* -datadir arg for DeepOnion-cli. */
	char *datadir;

	/* DeepOniond's version, used for compatibility checks. */
	u32 version;

	/* Is DeepOniond synced?  If not, we retry. */
	bool synced;

	/* How many high/low prio requests are we running (it's ratelimited) */
	size_t num_requests[DEEPONIOND_NUM_PRIO];

	/* Pending requests (high and low prio). */
	struct list_head pending[DEEPONIOND_NUM_PRIO];

	/* In flight requests (in a list for memleak detection) */
	struct list_head current;

	/* If non-zero, time we first hit a DeepOniond error. */
	unsigned int error_count;
	struct timemono first_error_time;

	/* How long to keep trying to contact DeepOniond
	 * before fatally exiting. */
	u64 retry_timeout;

	/* Passthrough parameters for DeepOnion-cli */
	char *rpcuser, *rpcpass, *rpcconnect, *rpcport;
	u64 rpcclienttimeout;

	/* Whether we fake fees (regtest) */
	bool fake_fees;

	/* Override in case we're developer mode for testing*/
	bool dev_no_fake_fees;
};

static struct deeponiond *deeponiond;

struct deeponion_cli {
	struct list_node list;
	int fd;
	int *exitstatus;
	pid_t pid;
	const char **args;
	struct timeabs start;
	enum deeponiond_prio prio;
	char *output;
	size_t output_bytes;
	size_t new_output;
	struct command_result *(*process)(struct deeponion_cli *);
	struct command *cmd;
	/* Used to stash content between multiple calls */
	void *stash;
};

/* Add the n'th arg to *args, incrementing n and keeping args of size n+1 */
static void add_arg(const char ***args, const char *arg TAKES)
{
	if (taken(arg))
		tal_steal(*args, arg);
	tal_arr_expand(args, arg);
}

static const char **gather_argsv(const tal_t *ctx, const char *cmd, va_list ap)
{
	const char **args = tal_arr(ctx, const char *, 1);
	const char *arg;

	args[0] = deeponiond->cli ? deeponiond->cli : chainparams->cli;
	if (chainparams->cli_args)
		add_arg(&args, chainparams->cli_args);
	if (deeponiond->datadir)
		add_arg(&args,
			tal_fmt(args, "-datadir=%s", deeponiond->datadir));
	if (deeponiond->rpcclienttimeout) {
		/* Use the maximum value of rpcclienttimeout and retry_timeout
		   to avoid the deeponiond backend hanging for too long. */
		if (deeponiond->retry_timeout &&
		    deeponiond->retry_timeout > deeponiond->rpcclienttimeout)
			deeponiond->rpcclienttimeout =
			    deeponiond->retry_timeout;

		add_arg(&args, tal_fmt(args, "-rpcclienttimeout=%" PRIu64,
				       deeponiond->rpcclienttimeout));
	}
	if (deeponiond->rpcconnect)
		add_arg(&args, tal_fmt(args, "-rpcconnect=%s",
				       deeponiond->rpcconnect));
	if (deeponiond->rpcport)
		add_arg(&args,
			tal_fmt(args, "-rpcport=%s", deeponiond->rpcport));
	if (deeponiond->rpcuser)
		add_arg(&args,
			tal_fmt(args, "-rpcuser=%s", deeponiond->rpcuser));
	if (deeponiond->rpcpass)
		// Always pipe the rpcpassword via stdin. Do not pass it using
		// an
		// `-rpcpassword` argument - secrets in arguments can leak when
		// listing system processes.
		add_arg(&args, "-stdinrpcpass");

	add_arg(&args, cmd);
	while ((arg = va_arg(ap, char *)) != NULL)
		add_arg(&args, arg);
	add_arg(&args, NULL);

	return args;
}

static LAST_ARG_NULL const char **gather_args(const tal_t *ctx, const char *cmd,
					      ...)
{
	va_list ap;
	const char **ret;

	va_start(ap, cmd);
	ret = gather_argsv(ctx, cmd, ap);
	va_end(ap);

	return ret;
}

static struct io_plan *read_more(struct io_conn *conn,
				 struct deeponion_cli *docli)
{
	docli->output_bytes += docli->new_output;
	if (docli->output_bytes == tal_count(docli->output))
		tal_resize(&docli->output, docli->output_bytes * 2);
	return io_read_partial(conn, docli->output + docli->output_bytes,
			       tal_count(docli->output) - docli->output_bytes,
			       &docli->new_output, read_more, docli);
}

static struct io_plan *output_init(struct io_conn *conn,
				   struct deeponion_cli *docli)
{
	docli->output_bytes = docli->new_output = 0;
	docli->output = tal_arr(docli, char, 100);
	return read_more(conn, docli);
}

static void next_bcli(enum deeponiond_prio prio);

/* For printing: simple string of args (no secrets!) */
static char *args_string(const tal_t *ctx, const char **args)
{
	size_t i;
	char *ret = tal_strdup(ctx, args[0]);

	for (i = 1; args[i]; i++) {
		ret = tal_strcat(ctx, take(ret), " ");
		if (strstarts(args[i], "-rpcpassword")) {
			ret = tal_strcat(ctx, take(ret), "-rpcpassword=...");
		} else if (strstarts(args[i], "-rpcuser")) {
			ret = tal_strcat(ctx, take(ret), "-rpcuser=...");
		} else {
			ret = tal_strcat(ctx, take(ret), args[i]);
		}
	}
	return ret;
}

static char *bcli_args(const tal_t *ctx, struct deeponion_cli *docli)
{
	return args_string(ctx, docli->args);
}

/* Only set as destructor once docli is in current. */
static void destroy_docli(struct deeponion_cli *docli)
{
	list_del_from(&deeponiond->current, &docli->list);
}

static struct command_result *retry_bcli(struct command *cmd,
					 struct deeponion_cli *docli)
{
	list_del_from(&deeponiond->current, &docli->list);
	tal_del_destructor(docli, destroy_docli);

	list_add_tail(&deeponiond->pending[docli->prio], &docli->list);
	tal_free(docli->output);
	next_bcli(docli->prio);
	return timer_complete(cmd);
}

/* We allow 60 seconds of spurious errors, eg. reorg. */
static void bcli_failure(struct deeponion_cli *docli, int exitstatus)
{
	struct timerel t;

	if (!deeponiond->error_count)
		deeponiond->first_error_time = time_mono();

	t = timemono_between(time_mono(), deeponiond->first_error_time);
	if (time_greater(t, time_from_sec(deeponiond->retry_timeout)))
		plugin_err(
		    docli->cmd->plugin,
		    "%s exited %u (after %u other errors) '%.*s'; "
		    "we have been retrying command for "
		    "--deeponion-retry-timeout=%" PRIu64 " seconds; "
		    "DeepOniond setup or our --deeponion-* configs broken?",
		    bcli_args(tmpctx, docli), exitstatus,
		    deeponiond->error_count, (int)docli->output_bytes,
		    docli->output, deeponiond->retry_timeout);

	plugin_log(docli->cmd->plugin, LOG_UNUSUAL, "%s exited with status %u",
		   bcli_args(tmpctx, docli), exitstatus);
	deeponiond->error_count++;

	/* Retry in 1 second */
	command_timer(docli->cmd, time_from_sec(1), retry_bcli, docli);
}

static void docli_finished(struct io_conn *conn UNUSED,
			   struct deeponion_cli *docli)
{
	int ret, status;
	struct command_result *res;
	enum deeponiond_prio prio = docli->prio;
	u64 msec = time_to_msec(time_between(time_now(), docli->start));

	/* If it took over 10 seconds, that's rather strange. */
	if (msec > 10000)
		plugin_log(docli->cmd->plugin, LOG_UNUSUAL,
			   "DeepOnion-cli: finished %s (%" PRIu64 " ms)",
			   bcli_args(tmpctx, docli), msec);

	assert(deeponiond->num_requests[prio] > 0);

	/* FIXME: If we waited for SIGCHILD, this could never hang! */
	while ((ret = waitpid(docli->pid, &status, 0)) < 0 && errno == EINTR)
		;
	if (ret != docli->pid)
		plugin_err(docli->cmd->plugin, "%s %s",
			   bcli_args(tmpctx, docli),
			   ret == 0 ? "not exited?" : strerror(errno));

	if (!WIFEXITED(status))
		plugin_err(docli->cmd->plugin, "%s died with signal %i",
			   bcli_args(tmpctx, docli), WTERMSIG(status));

	/* Implicit nonzero_exit_ok == false */
	if (!docli->exitstatus) {
		if (WEXITSTATUS(status) != 0) {
			bcli_failure(docli, WEXITSTATUS(status));
			deeponiond->num_requests[prio]--;
			goto done;
		}
	} else
		*docli->exitstatus = WEXITSTATUS(status);

	if (WEXITSTATUS(status) == 0)
		deeponiond->error_count = 0;

	deeponiond->num_requests[docli->prio]--;

	res = docli->process(docli);
	if (!res)
		bcli_failure(docli, WEXITSTATUS(status));
	else
		tal_free(docli);

done:
	next_bcli(prio);
}

static void next_bcli(enum deeponiond_prio prio)
{
	struct deeponion_cli *docli;
	struct io_conn *conn;
	int in;

	if (deeponiond->num_requests[prio] >= DEEPONIOND_MAX_PARALLEL)
		return;

	docli =
	    list_pop(&deeponiond->pending[prio], struct deeponion_cli, list);
	if (!docli)
		return;

	docli->pid = pipecmdarr(&in, &docli->fd, &docli->fd,
				cast_const2(char **, docli->args));
	if (docli->pid < 0)
		plugin_err(docli->cmd->plugin, "%s exec failed: %s",
			   docli->args[0], strerror(errno));

	if (deeponiond->rpcpass)
		write_all(in, deeponiond->rpcpass, strlen(deeponiond->rpcpass));

	close(in);

	docli->start = time_now();

	deeponiond->num_requests[prio]++;

	/* We don't keep a pointer to this, but it's not a leak */
	conn = notleak(io_new_conn(docli, docli->fd, output_init, docli));
	io_set_finish(conn, docli_finished, docli);

	list_add_tail(&deeponiond->current, &docli->list);
	tal_add_destructor(docli, destroy_docli);
}

static void
start_deeponion_cliv(const tal_t *ctx, struct command *cmd,
		     struct command_result *(*process)(struct deeponion_cli *),
		     bool nonzero_exit_ok, enum deeponiond_prio prio,
		     void *stash, const char *method, va_list ap)
{
	struct deeponion_cli *docli = tal(deeponiond, struct deeponion_cli);

	docli->process = process;
	docli->cmd = cmd;
	docli->prio = prio;

	if (nonzero_exit_ok)
		docli->exitstatus = tal(docli, int);
	else
		docli->exitstatus = NULL;

	docli->args = gather_argsv(docli, method, ap);
	docli->stash = stash;

	list_add_tail(&deeponiond->pending[docli->prio], &docli->list);
	next_bcli(docli->prio);
}

/* If ctx is non-NULL, and is freed before we return, we don't call process().
 * process returns false() if it's a spurious error, and we should retry. */
static void LAST_ARG_NULL
start_deeponion_cli(const tal_t *ctx, struct command *cmd,
		    struct command_result *(*process)(struct deeponion_cli *),
		    bool nonzero_exit_ok, enum deeponiond_prio prio,
		    void *stash, const char *method, ...)
{
	va_list ap;

	va_start(ap, method);
	start_deeponion_cliv(ctx, cmd, process, nonzero_exit_ok, prio, stash,
			     method, ap);
	va_end(ap);
}

static void strip_trailing_whitespace(char *str, size_t len)
{
	size_t stripped_len = len;
	while (stripped_len > 0 && cisspace(str[stripped_len - 1]))
		stripped_len--;

	str[stripped_len] = 0x00;
}

static struct command_result *
command_err_bcli_badjson(struct deeponion_cli *docli, const char *errmsg)
{
	char *err =
	    tal_fmt(docli, "%s: bad JSON: %s (%.*s)", bcli_args(tmpctx, docli),
		    errmsg, (int)docli->output_bytes, docli->output);
	return command_done_err(docli->cmd, BCLI_ERROR, err, NULL);
}

static struct command_result *process_getutxout(struct deeponion_cli *docli)
{
	const jsmntok_t *tokens;
	struct json_stream *response;
	struct bitcoin_tx_output output;
	const char *err;

	/* As of at least v0.15.1.0, DeepOniond returns "success" but an empty
	   string on a spent txout. */
	if (*docli->exitstatus != 0 || docli->output_bytes == 0) {
		response = jsonrpc_stream_success(docli->cmd);
		json_add_null(response, "amount");
		json_add_null(response, "script");

		return command_finished(docli->cmd, response);
	}

	tokens = json_parse_simple(docli->output, docli->output,
				   docli->output_bytes);
	if (!tokens) {
		return command_err_bcli_badjson(docli, "cannot parse");
	}

	err = json_scan(
	    tmpctx, docli->output, tokens, "{value:%,scriptPubKey:{hex:%}}",
	    JSON_SCAN(json_to_bitcoin_amount,
		      &output.amount.satoshis), /* Raw: DeepOniond */
	    JSON_SCAN_TAL(docli, json_tok_bin_from_hex, &output.script));
	if (err)
		return command_err_bcli_badjson(docli, err);

	response = jsonrpc_stream_success(docli->cmd);
	json_add_sats(response, "amount", output.amount);
	json_add_string(response, "script", tal_hex(response, output.script));

	return command_finished(docli->cmd, response);
}

static struct command_result *
process_getblockchaininfo(struct deeponion_cli *docli)
{
	const jsmntok_t *tokens;
	struct json_stream *response;
	bool ibd;
	u32 headers, blocks;
	const char *chain, *err;

	tokens = json_parse_simple(docli->output, docli->output,
				   docli->output_bytes);
	if (!tokens) {
		return command_err_bcli_badjson(docli, "cannot parse");
	}

	err = json_scan(tmpctx, docli->output, tokens,
			"{chain:%,headers:%,blocks:%,initialblockdownload:%}",
			JSON_SCAN_TAL(tmpctx, json_strdup, &chain),
			JSON_SCAN(json_to_number, &headers),
			JSON_SCAN(json_to_number, &blocks),
			JSON_SCAN(json_to_bool, &ibd));
	if (err)
		return command_err_bcli_badjson(docli, err);

	response = jsonrpc_stream_success(docli->cmd);
	json_add_string(response, "chain", chain);
	json_add_u32(response, "headercount", headers);
	json_add_u32(response, "blockcount", blocks);
	json_add_bool(response, "ibd", ibd);

	return command_finished(docli->cmd, response);
}

struct estimatefee_params {
	u32 blocks;
	const char *style;
};

static const struct estimatefee_params estimatefee_params[] = {
    {2, "CONSERVATIVE"},
    {6, "ECONOMICAL"},
    {12, "ECONOMICAL"},
    {100, "ECONOMICAL"},
};

struct estimatefees_stash {
	/* This is max(mempoolminfee,minrelaytxfee) */
	u64 perkb_floor;
	u32 cursor;
	/* FIXME: We use u64 but lightningd will store them as u32. */
	u64 perkb[ARRAY_SIZE(estimatefee_params)];
};

static struct command_result *
estimatefees_null_response(struct deeponion_cli *docli)
{
	struct json_stream *response = jsonrpc_stream_success(docli->cmd);

	/* We give a floor, which is the standard minimum */
	json_array_start(response, "feerates");
	json_array_end(response);
	json_add_u32(response, "feerate_floor", 1000);

	return command_finished(docli->cmd, response);
}

static struct command_result *
estimatefees_parse_feerate(struct deeponion_cli *docli, u64 *feerate)
{
	const jsmntok_t *tokens;

	tokens = json_parse_simple(docli->output, docli->output,
				   docli->output_bytes);
	if (!tokens) {
		return command_err_bcli_badjson(docli, "cannot parse");
	}

	if (json_scan(tmpctx, docli->output, tokens, "{feerate:%}",
		      JSON_SCAN(json_to_bitcoin_amount, feerate)) != NULL) {
		/* Paranoia: if it had a feerate, but was malformed: */
		if (json_get_member(docli->output, tokens, "feerate"))
			return command_err_bcli_badjson(docli, "cannot scan");
		/* Regtest fee estimation is generally awful: Fake it at min. */
		if (deeponiond->fake_fees) {
			*feerate = 1000;
			return NULL;
		}
		/* We return null if estimation failed, and DeepOnion-cli will
		 * exit with 0 but no feerate field on failure. */
		return estimatefees_null_response(docli);
	}

	return NULL;
}

static struct command_result *
process_sendrawtransaction(struct deeponion_cli *docli)
{
	struct json_stream *response;

	/* This is useful for functional tests. */
	if (docli->exitstatus)
		plugin_log(
		    docli->cmd->plugin, LOG_DBG, "sendrawtx exit %i (%s) %.*s",
		    *docli->exitstatus, bcli_args(tmpctx, docli),
		    *docli->exitstatus ? (u32)docli->output_bytes - 1 : 0,
		    docli->output);

	response = jsonrpc_stream_success(docli->cmd);
	json_add_bool(response, "success",
		      *docli->exitstatus == 0 ||
			  *docli->exitstatus ==
			      RPC_TRANSACTION_ALREADY_IN_CHAIN);
	json_add_string(response, "errmsg",
			*docli->exitstatus
			    ? tal_strndup(docli->cmd, docli->output,
					  docli->output_bytes - 1)
			    : "");

	return command_finished(docli->cmd, response);
}

struct getrawblock_stash {
	const char *block_hash;
	u32 block_height;
	const char *block_hex;
	int *peers;
};

/* Mutual recursion. */
static struct command_result *getrawblock(struct deeponion_cli *docli);

static struct command_result *process_rawblock(struct deeponion_cli *docli)
{
	struct json_stream *response;
	struct getrawblock_stash *stash = docli->stash;

	strip_trailing_whitespace(docli->output, docli->output_bytes);
	stash->block_hex = tal_steal(stash, docli->output);

	response = jsonrpc_stream_success(docli->cmd);
	json_add_string(response, "blockhash", stash->block_hash);
	json_add_string(response, "block", stash->block_hex);

	return command_finished(docli->cmd, response);
}

static struct command_result *
process_getblockfrompeer(struct deeponion_cli *docli)
{
	/* Remove the peer that we tried to get the block from and move along,
	 * we may also check on errors here */
	struct getrawblock_stash *stash = docli->stash;

	if (docli->exitstatus && *docli->exitstatus != 0) {
		/* We still continue with the execution if we can not fetch the
		 * block from peer */
		plugin_log(docli->cmd->plugin, LOG_DBG,
			   "failed to fetch block %s from peer %i, skip.",
			   stash->block_hash,
			   stash->peers[tal_count(stash->peers) - 1]);
	} else {
		plugin_log(docli->cmd->plugin, LOG_DBG,
			   "try to fetch block %s from peer %i.",
			   stash->block_hash,
			   stash->peers[tal_count(stash->peers) - 1]);
	}
	tal_resize(&stash->peers, tal_count(stash->peers) - 1);

	/* `getblockfrompeer` is an async call. sleep for a second to allow the
	 * block to be delivered by the peer. fixme: We could also sleep for
	 * double the last ping here (with sanity limit)*/
	sleep(1);

	return getrawblock(docli);
}

static struct command_result *process_getpeerinfo(struct deeponion_cli *docli)
{
	const jsmntok_t *t, *toks;
	struct getrawblock_stash *stash = docli->stash;
	size_t i;

	toks = json_parse_simple(docli->output, docli->output,
				 docli->output_bytes);

	if (!toks) {
		return command_err_bcli_badjson(docli, "cannot parse");
	}

	stash->peers = tal_arr(docli->stash, int, 0);

	json_for_each_arr(i, t, toks)
	{
		int id;
		if (json_scan(tmpctx, docli->output, t, "{id:%}",
			      JSON_SCAN(json_to_int, &id)) == NULL) {
			// fixme: future optimization: a) filter for full nodes,
			// b) sort by last ping
			tal_arr_expand(&stash->peers, id);
		}
	}

	if (tal_count(stash->peers) <= 0) {
		/* We don't have peers yet, retry from `getrawblock` */
		plugin_log(docli->cmd->plugin, LOG_DBG,
			   "got an empty peer list.");
		return getrawblock(docli);
	}

	start_deeponion_cli(NULL, docli->cmd, process_getblockfrompeer, true,
			    BITCOIND_HIGH_PRIO, stash, "getblockfrompeer",
			    stash->block_hash,
			    take(tal_fmt(NULL, "%i", stash->peers[0])), NULL);

	return command_still_pending(docli->cmd);
}

static struct command_result *process_getrawblock(struct deeponion_cli *docli)
{
	/* We failed to get the raw block. */
	if (docli->exitstatus && *docli->exitstatus != 0) {
		struct getrawblock_stash *stash = docli->stash;

		plugin_log(
		    docli->cmd->plugin, LOG_DBG,
		    "failed to fetch block %s from the DeepOnion backend "
		    "(maybe pruned).",
		    stash->block_hash);

		if (deeponiond->version >= 230000) {
			/* `getblockformpeer` was introduced in v23.0.0 */

			if (!stash->peers) {
				/* We don't have peers to fetch blocks from, get
				 * some! */
				start_deeponion_cli(NULL, docli->cmd,
						    process_getpeerinfo, true,
						    BITCOIND_HIGH_PRIO, stash,
						    "getpeerinfo", NULL);

				return command_still_pending(docli->cmd);
			}

			if (tal_count(stash->peers) > 0) {
				/* We have peers left that we can ask for the
				 * block */
				start_deeponion_cli(
				    NULL, docli->cmd, process_getblockfrompeer,
				    true, BITCOIND_HIGH_PRIO, stash,
				    "getblockfrompeer", stash->block_hash,
				    take(tal_fmt(NULL, "%i", stash->peers[0])),
				    NULL);

				return command_still_pending(docli->cmd);
			}

			/* We failed to fetch the block from from any peer we
			 * got. */
			plugin_log(
			    docli->cmd->plugin, LOG_DBG,
			    "asked all known peers about block %s, retry",
			    stash->block_hash);
			stash->peers = tal_free(stash->peers);
		}

		return NULL;
	}

	return process_rawblock(docli);
}

static struct command_result *
getrawblockbyheight_notfound(struct deeponion_cli *docli)
{
	struct json_stream *response;

	response = jsonrpc_stream_success(docli->cmd);
	json_add_null(response, "blockhash");
	json_add_null(response, "block");

	return command_finished(docli->cmd, response);
}

static struct command_result *getrawblock(struct deeponion_cli *docli)
{
	struct getrawblock_stash *stash = docli->stash;

	start_deeponion_cli(NULL, docli->cmd, process_getrawblock, true,
			    BITCOIND_HIGH_PRIO, stash, "getblock",
			    stash->block_hash,
			    /* Non-verbose: raw block. */
			    "0", NULL);

	return command_still_pending(docli->cmd);
}

static struct command_result *process_getblockhash(struct deeponion_cli *docli)
{
	struct getrawblock_stash *stash = docli->stash;

	/* If it failed with error 8, give an empty response. */
	if (docli->exitstatus && *docli->exitstatus != 0) {
		/* Other error means we have to retry. */
		if (*docli->exitstatus != 8)
			return NULL;
		return getrawblockbyheight_notfound(docli);
	}

	strip_trailing_whitespace(docli->output, docli->output_bytes);
	stash->block_hash = tal_strdup(stash, docli->output);
	if (!stash->block_hash || strlen(stash->block_hash) != 64) {
		return command_err_bcli_badjson(docli, "bad blockhash");
	}

	return getrawblock(docli);
}

/* Get a raw block given its height.
 * Calls `getblockhash` then `getblock` to retrieve it from deeponion_cli.
 * Will return early with null fields if block isn't known (yet).
 */
static struct command_result *
getrawblockbyheight(struct command *cmd, const char *buf, const jsmntok_t *toks)
{
	struct getrawblock_stash *stash;
	u32 *height;

	/* DeepOnion-cli wants a string. */
	if (!param(cmd, buf, toks, p_req("height", param_number, &height),
		   NULL))
		return command_param_failed();

	stash = tal(cmd, struct getrawblock_stash);
	stash->block_height = *height;
	stash->peers = NULL;
	tal_free(height);

	start_deeponion_cli(NULL, cmd, process_getblockhash, true,
			    BITCOIND_LOW_PRIO, stash, "getblockhash",
			    take(tal_fmt(NULL, "%u", stash->block_height)),
			    NULL);

	return command_still_pending(cmd);
}

/* Get infos about the block chain.
 * Calls `getblockchaininfo` and returns headers count, blocks count,
 * the chain id, and whether this is initialblockdownload.
 */
static struct command_result *getchaininfo(struct command *cmd,
					   const char *buf UNUSED,
					   const jsmntok_t *toks UNUSED)
{
	/* FIXME(vincenzopalazzo): Inside the JSON request,
	 * we have the current height known from Core Lightning. Therefore,
	 * we can attempt to prevent a crash if the 'getchaininfo' function
	 * returns a lower height than the one we already know, by waiting for a
	 * short period. However, I currently don't have a better idea on how to
	 * handle this situation. */
	u32 *height UNUSED;
	if (!param(cmd, buf, toks, p_opt("last_height", param_number, &height),
		   NULL))
		return command_param_failed();

	start_deeponion_cli(NULL, cmd, process_getblockchaininfo, false,
			    BITCOIND_HIGH_PRIO, NULL, "getblockchaininfo",
			    NULL);

	return command_still_pending(cmd);
}

/* Mutual recursion. */
static struct command_result *estimatefees_done(struct deeponion_cli *docli);

/* Add a feerate, but don't publish one that DeepOniond won't accept. */
static void json_add_feerate(struct json_stream *result, const char *fieldname,
			     struct command *cmd,
			     const struct estimatefees_stash *stash,
			     uint64_t value)
{
	/* Anthony Towns reported signet had a 900kbtc fee block, and then
	 * CLN got upset scanning feerate.  It expects a u32. */
	if (value > 0xFFFFFFFF) {
		plugin_log(cmd->plugin, LOG_UNUSUAL,
			   "Feerate %" PRIu64
			   " is ridiculous: trimming to 32 bites",
			   value);
		value = 0xFFFFFFFF;
	}
	/* 0 is special, it means "unknown" */
	if (value && value < stash->perkb_floor) {
		plugin_log(cmd->plugin, LOG_DBG,
			   "Feerate %s raised from %" PRIu64
			   " perkb to floor of %" PRIu64,
			   fieldname, value, stash->perkb_floor);
		json_add_u64(result, fieldname, stash->perkb_floor);
	} else {
		json_add_u64(result, fieldname, value);
	}
}

static struct command_result *
estimatefees_next(struct command *cmd, struct estimatefees_stash *stash)
{
	struct json_stream *response;

	if (stash->cursor < ARRAY_SIZE(stash->perkb)) {
		start_deeponion_cli(
		    NULL, cmd, estimatefees_done, true, BITCOIND_LOW_PRIO,
		    stash, "estimatesmartfee",
		    take(tal_fmt(NULL, "%u",
				 estimatefee_params[stash->cursor].blocks)),
		    estimatefee_params[stash->cursor].style, NULL);

		return command_still_pending(cmd);
	}

	response = jsonrpc_stream_success(cmd);
	/* Present an ordered array of block deadlines, and a floor. */
	json_array_start(response, "feerates");
	for (size_t i = 0; i < ARRAY_SIZE(stash->perkb); i++) {
		if (!stash->perkb[i])
			continue;
		json_object_start(response, NULL);
		json_add_u32(response, "blocks", estimatefee_params[i].blocks);
		json_add_feerate(response, "feerate", cmd, stash,
				 stash->perkb[i]);
		json_object_end(response);
	}
	json_array_end(response);
	json_add_u64(response, "feerate_floor", stash->perkb_floor);
	return command_finished(cmd, response);
}

static struct command_result *getminfees_done(struct deeponion_cli *docli)
{
	const jsmntok_t *tokens;
	const char *err;
	u64 mempoolfee, relayfee;
	struct estimatefees_stash *stash = docli->stash;

	if (*docli->exitstatus != 0)
		return estimatefees_null_response(docli);

	tokens = json_parse_simple(docli->output, docli->output,
				   docli->output_bytes);
	if (!tokens)
		return command_err_bcli_badjson(docli,
						"cannot parse getmempoolinfo");

	/* Look at minrelaytxfee they configured, and current min fee to get
	 * into mempool. */
	err = json_scan(tmpctx, docli->output, tokens,
			"{mempoolminfee:%,minrelaytxfee:%}",
			JSON_SCAN(json_to_bitcoin_amount, &mempoolfee),
			JSON_SCAN(json_to_bitcoin_amount, &relayfee));
	if (err)
		return command_err_bcli_badjson(docli, err);

	stash->perkb_floor = max_u64(mempoolfee, relayfee);
	stash->cursor = 0;
	return estimatefees_next(docli->cmd, stash);
}

/* Get the current feerates. We use an urgent feerate for unilateral_close and
 * max, a slightly less urgent feerate for htlc_resolution and penalty
 * transactions, a slow feerate for min, and a normal one for all others.
 */
static struct command_result *estimatefees(struct command *cmd,
					   const char *buf UNUSED,
					   const jsmntok_t *toks UNUSED)
{
	struct estimatefees_stash *stash = tal(cmd, struct estimatefees_stash);

	if (!param(cmd, buf, toks, NULL))
		return command_param_failed();

	start_deeponion_cli(NULL, cmd, getminfees_done, true, BITCOIND_LOW_PRIO,
			    stash, "getmempoolinfo", NULL);
	return command_still_pending(cmd);
}

static struct command_result *estimatefees_done(struct deeponion_cli *docli)
{
	struct command_result *err;
	struct estimatefees_stash *stash = docli->stash;

	/* If we cannot estimate fees, no need to continue bothering DeepOniond.
	 */
	if (*docli->exitstatus != 0)
		return estimatefees_null_response(docli);

	err = estimatefees_parse_feerate(docli, &stash->perkb[stash->cursor]);
	if (err)
		return err;

	stash->cursor++;
	return estimatefees_next(docli->cmd, stash);
}

/* Send a transaction to the Bitcoin network.
 * Calls `sendrawtransaction` using the first parameter as the raw tx.
 */
static struct command_result *
sendrawtransaction(struct command *cmd, const char *buf, const jsmntok_t *toks)
{
	const char *tx, *highfeesarg;
	bool *allowhighfees;

	/* DeepOnion-cli wants strings. */
	if (!param(cmd, buf, toks, p_req("tx", param_string, &tx),
		   p_req("allowhighfees", param_bool, &allowhighfees), NULL))
		return command_param_failed();

	if (*allowhighfees) {
		highfeesarg = "0";
	} else
		highfeesarg = NULL;

	start_deeponion_cli(NULL, cmd, process_sendrawtransaction, true,
			    BITCOIND_HIGH_PRIO, NULL, "sendrawtransaction", tx,
			    highfeesarg, NULL);

	return command_still_pending(cmd);
}

static struct command_result *getutxout(struct command *cmd, const char *buf,
					const jsmntok_t *toks)
{
	const char *txid, *vout;

	/* DeepOnion-cli wants strings. */
	if (!param(cmd, buf, toks, p_req("txid", param_string, &txid),
		   p_req("vout", param_string, &vout), NULL))
		return command_param_failed();

	start_deeponion_cli(NULL, cmd, process_getutxout, true,
			    BITCOIND_HIGH_PRIO, NULL, "gettxout", txid, vout,
			    NULL);

	return command_still_pending(cmd);
}

static void bitcoind_failure(struct plugin *p, const char *error_message)
{
	const char **cmd = gather_args(deeponiond, "echo", NULL);
	plugin_err(
	    p,
	    "\n%s\n\n"
	    "Make sure you have DeepOniond running and that DeepOnion-cli"
	    " is able to connect to DeepOniond.\n\n"
	    "You can verify that your DeepOnion installation is"
	    " ready for use by running:\n\n"
	    "    $ %s 'hello world'\n",
	    error_message, args_string(cmd, cmd));
}

/* Do some sanity checks on DeepOniond based on the output of `getnetworkinfo`.
 */
static void parse_getnetworkinfo_result(struct plugin *p, const char *buf)
{
	const jsmntok_t *result;
	bool tx_relay;
	u32 min_version = 220000;
	const char *err;

	result = json_parse_simple(NULL, buf, strlen(buf));
	if (!result)
		plugin_err(
		    p,
		    "Invalid response to '%s': '%s'. Can not "
		    "continue without proceeding to sanity checks.",
		    args_string(tmpctx, gather_args(deeponiond,
						    "getnetworkinfo", NULL)),
		    buf);

	/* Check that we have a fully-featured `estimatesmartfee`. */
	err = json_scan(tmpctx, buf, result, "{version:%,localrelay:%}",
			JSON_SCAN(json_to_u32, &deeponiond->version),
			JSON_SCAN(json_to_bool, &tx_relay));
	if (err)
		plugin_err(p,
			   "%s.  Got '%.*s'. Can not"
			   " continue without proceeding to sanity checks.",
			   err, json_tok_full_len(result),
			   json_tok_full(buf, result));

	if (deeponiond->version < min_version)
		plugin_err(p,
			   "Unsupported DeepOniond version %" PRIu32
			   ", at least"
			   " %" PRIu32 " required.",
			   deeponiond->version, min_version);

	/* We don't support 'blocksonly', as we rely on transaction relay for
	 * fee estimates. */
	if (!tx_relay)
		plugin_err(p,
			   "The 'blocksonly' mode of DeepOniond, or any option "
			   "deactivating transaction relay is not supported.");

	tal_free(result);
}

static void wait_and_check_bitcoind(struct plugin *p)
{
	int in, from, status, ret;
	pid_t child;
	const char **cmd = gather_args(deeponiond, "getnetworkinfo", NULL);
	bool printed = false;
	char *output = NULL;

	for (;;) {
		tal_free(output);

		child =
		    pipecmdarr(&in, &from, &from, cast_const2(char **, cmd));

		if (deeponiond->rpcpass)
			write_all(in, deeponiond->rpcpass,
				  strlen(deeponiond->rpcpass));

		close(in);

		if (child < 0) {
			if (errno == ENOENT)
				bitcoind_failure(
				    p,
				    "DeepOnion-cli not found. Is DeepOnion-cli "
				    "(part of DeepOnion) available in "
				    "your PATH?");
			plugin_err(p, "%s exec failed: %s", cmd[0],
				   strerror(errno));
		}

		output = grab_fd(cmd, from);

		while ((ret = waitpid(child, &status, 0)) < 0 && errno == EINTR)
			;
		if (ret != child)
			bitcoind_failure(p, tal_fmt(deeponiond,
						    "Waiting for %s: %s",
						    cmd[0], strerror(errno)));
		if (!WIFEXITED(status))
			bitcoind_failure(p, tal_fmt(deeponiond,
						    "Death of %s: signal %i",
						    cmd[0], WTERMSIG(status)));

		if (WEXITSTATUS(status) == 0)
			break;

		/* deeponion/src/rpc/protocol.h:
		 *	RPC_IN_WARMUP = -28, //!< Client still warming up
		 */
		if (WEXITSTATUS(status) != 28) {
			if (WEXITSTATUS(status) == 1)
				bitcoind_failure(
				    p,
				    "Could not connect to DeepOniond using"
				    " DeepOnion-cli. Is DeepOniond running?");
			bitcoind_failure(
			    p, tal_fmt(deeponiond, "%s exited with code %i: %s",
				       cmd[0], WEXITSTATUS(status), output));
		}

		if (!printed) {
			plugin_log(p, LOG_UNUSUAL,
				   "Waiting for DeepOniond to warm up...");
			printed = true;
		}
		sleep(1);
	}

	parse_getnetworkinfo_result(p, output);

	tal_free(cmd);
}

static void memleak_mark_bitcoind(struct plugin *p, struct htable *memtable)
{
	memleak_scan_obj(memtable, deeponiond);
}

static const char *init(struct command *init_cmd, const char *buffer UNUSED,
			const jsmntok_t *config UNUSED)
{
	wait_and_check_bitcoind(init_cmd->plugin);

	/* Usually we fake up fees in regtest */
	if (streq(chainparams->network_name, "regtest"))
		deeponiond->fake_fees = !deeponiond->dev_no_fake_fees;
	else
		deeponiond->fake_fees = false;

	plugin_set_memleak_handler(init_cmd->plugin, memleak_mark_bitcoind);
	plugin_log(init_cmd->plugin, LOG_INFORM,
		   "DeepOnion-cli initialized and connected to DeepOniond.");

	return NULL;
}

static const struct plugin_command commands[] = {
    {"getrawblockbyheight", getrawblockbyheight},
    {"getchaininfo", getchaininfo},
    {"estimatefees", estimatefees},
    {"sendrawtransaction", sendrawtransaction},
    {"getutxout", getutxout},
};

static struct deeponiond *new_bitcoind(const tal_t *ctx)
{
	deeponiond = tal(ctx, struct deeponiond);

	deeponiond->cli = NULL;
	deeponiond->datadir = NULL;
	for (size_t i = 0; i < DEEPONIOND_NUM_PRIO; i++) {
		deeponiond->num_requests[i] = 0;
		list_head_init(&deeponiond->pending[i]);
	}
	list_head_init(&deeponiond->current);
	deeponiond->error_count = 0;
	deeponiond->retry_timeout = 60;
	deeponiond->rpcuser = NULL;
	deeponiond->rpcpass = NULL;
	deeponiond->rpcconnect = NULL;
	deeponiond->rpcport = NULL;
	/* Do not exceed retry_timeout value to avoid a DeepOniond hang,
	   although normal rpcclienttimeout default value is 900. */
	deeponiond->rpcclienttimeout = 60;
	deeponiond->dev_no_fake_fees = false;

	return deeponiond;
}

int main(int argc, char *argv[])
{
	setup_locale();

	/* Initialize our global context object here to handle startup options.
	 */
	deeponiond = new_bitcoind(NULL);

	plugin_main(
	    argv, init, NULL, PLUGIN_STATIC,
	    false /* Do not init RPC on startup*/, NULL, commands,
	    ARRAY_SIZE(commands), NULL, 0, NULL, 0, NULL, 0,
	    plugin_option("deeponion-datadir", "string",
			  "-datadir arg for DeepOnion-cli", charp_option, NULL,
			  &deeponiond->datadir),
	    plugin_option("deeponion-cli", "string", "DeepOnion-cli pathname",
			  charp_option, NULL, &deeponiond->cli),
	    plugin_option("deeponion-rpcuser", "string",
			  "DeepOniond RPC username", charp_option, NULL,
			  &deeponiond->rpcuser),
	    plugin_option("deeponion-rpcpassword", "string",
			  "DeepOniond RPC password", charp_option, NULL,
			  &deeponiond->rpcpass),
	    plugin_option("deeponion-rpcconnect", "string",
			  "DeepOniond RPC host to connect to", charp_option,
			  NULL, &deeponiond->rpcconnect),
	    plugin_option("deeponion-rpcport", "int",
			  "DeepOniond RPC host's port", charp_option, NULL,
			  &deeponiond->rpcport),
	    plugin_option(
		"deeponion-rpcclienttimeout", "int",
		"DeepOniond RPC timeout in seconds during HTTP requests",
		u64_option, u64_jsonfmt, &deeponiond->rpcclienttimeout),
	    plugin_option("deeponion-retry-timeout", "int",
			  "how long to keep retrying to contact DeepOniond"
			  " before fatally exiting",
			  u64_option, u64_jsonfmt, &deeponiond->retry_timeout),
	    plugin_option_dev("dev-no-fake-fees", "bool",
			      "Suppress fee faking for regtest", bool_option,
			      NULL, &deeponiond->dev_no_fake_fees),
	    NULL);
}
