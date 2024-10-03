#include "config.h"
#include "../amount.c"
#include "../json_filter.c"
#include "../json_param.c"
#include "../json_parse_simple.c"
#include "../json_stream.c"
#include <ccan/json_out/json_out.h>
#include <common/json_command.h>
#include <common/setup.h>
#include <stdio.h>

struct command;

/* AUTOGENERATED MOCKS START */
/* Generated stub for command_check_done */
struct command_result *command_check_done(struct command *cmd)

{ fprintf(stderr, "command_check_done called!\n"); abort(); }
/* Generated stub for command_check_only */
bool command_check_only(const struct command *cmd UNNEEDED)
{ fprintf(stderr, "command_check_only called!\n"); abort(); }
/* Generated stub for command_deprecated_in_ok */
bool command_deprecated_in_ok(struct command *cmd UNNEEDED,
			      const char *param UNNEEDED,
			      const char *depr_start UNNEEDED,
			      const char *depr_end UNNEEDED)
{ fprintf(stderr, "command_deprecated_in_ok called!\n"); abort(); }
/* Generated stub for command_dev_apis */
bool command_dev_apis(const struct command *cmd UNNEEDED)
{ fprintf(stderr, "command_dev_apis called!\n"); abort(); }
/* Generated stub for command_fail */
struct command_result *command_fail(struct command *cmd UNNEEDED, enum jsonrpc_errcode code UNNEEDED,
				    const char *fmt UNNEEDED, ...)

{ fprintf(stderr, "command_fail called!\n"); abort(); }
/* Generated stub for command_fail_badparam */
struct command_result *command_fail_badparam(struct command *cmd UNNEEDED,
					     const char *paramname UNNEEDED,
					     const char *buffer UNNEEDED,
					     const jsmntok_t *tok UNNEEDED,
					     const char *msg UNNEEDED)
{ fprintf(stderr, "command_fail_badparam called!\n"); abort(); }
/* Generated stub for command_set_usage */
void command_set_usage(struct command *cmd UNNEEDED, const char *usage UNNEEDED)
{ fprintf(stderr, "command_set_usage called!\n"); abort(); }
/* Generated stub for command_usage_only */
bool command_usage_only(const struct command *cmd UNNEEDED)
{ fprintf(stderr, "command_usage_only called!\n"); abort(); }
/* Generated stub for fmt_wireaddr_without_port */
char *fmt_wireaddr_without_port(const tal_t *ctx UNNEEDED, const struct wireaddr *a UNNEEDED)
{ fprintf(stderr, "fmt_wireaddr_without_port called!\n"); abort(); }
/* Generated stub for fromwire */
const u8 *fromwire(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, void *copy UNNEEDED, size_t n UNNEEDED)
{ fprintf(stderr, "fromwire called!\n"); abort(); }
/* Generated stub for fromwire_bool */
bool fromwire_bool(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_bool called!\n"); abort(); }
/* Generated stub for fromwire_fail */
void *fromwire_fail(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_fail called!\n"); abort(); }
/* Generated stub for fromwire_secp256k1_ecdsa_signature */
void fromwire_secp256k1_ecdsa_signature(const u8 **cursor UNNEEDED, size_t *max UNNEEDED,
					secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "fromwire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for fromwire_sha256 */
void fromwire_sha256(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "fromwire_sha256 called!\n"); abort(); }
/* Generated stub for fromwire_tal_arrn */
u8 *fromwire_tal_arrn(const tal_t *ctx UNNEEDED,
		       const u8 **cursor UNNEEDED, size_t *max UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_tal_arrn called!\n"); abort(); }
/* Generated stub for fromwire_u32 */
u32 fromwire_u32(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u32 called!\n"); abort(); }
/* Generated stub for fromwire_u64 */
u64 fromwire_u64(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u64 called!\n"); abort(); }
/* Generated stub for fromwire_u8 */
u8 fromwire_u8(const u8 **cursor UNNEEDED, size_t *max UNNEEDED)
{ fprintf(stderr, "fromwire_u8 called!\n"); abort(); }
/* Generated stub for fromwire_u8_array */
void fromwire_u8_array(const u8 **cursor UNNEEDED, size_t *max UNNEEDED, u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "fromwire_u8_array called!\n"); abort(); }
/* Generated stub for json_scan */
const char *json_scan(const tal_t *ctx UNNEEDED,
		      const char *buffer UNNEEDED,
		      const jsmntok_t *tok UNNEEDED,
		      const char *guide UNNEEDED,
		      ...)
{ fprintf(stderr, "json_scan called!\n"); abort(); }
/* Generated stub for json_to_channel_id */
bool json_to_channel_id(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
			struct channel_id *cid UNNEEDED)
{ fprintf(stderr, "json_to_channel_id called!\n"); abort(); }
/* Generated stub for json_to_millionths */
bool json_to_millionths(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
			u64 *millionths UNNEEDED)
{ fprintf(stderr, "json_to_millionths called!\n"); abort(); }
/* Generated stub for json_to_msat */
bool json_to_msat(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		  struct amount_msat *msat UNNEEDED)
{ fprintf(stderr, "json_to_msat called!\n"); abort(); }
/* Generated stub for json_to_node_id */
bool json_to_node_id(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
			       struct node_id *id UNNEEDED)
{ fprintf(stderr, "json_to_node_id called!\n"); abort(); }
/* Generated stub for json_to_number */
bool json_to_number(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		    unsigned int *num UNNEEDED)
{ fprintf(stderr, "json_to_number called!\n"); abort(); }
/* Generated stub for json_to_outpoint */
bool json_to_outpoint(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		      struct bitcoin_outpoint *op UNNEEDED)
{ fprintf(stderr, "json_to_outpoint called!\n"); abort(); }
/* Generated stub for json_to_pubkey */
bool json_to_pubkey(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		    struct pubkey *pubkey UNNEEDED)
{ fprintf(stderr, "json_to_pubkey called!\n"); abort(); }
/* Generated stub for json_to_short_channel_id */
bool json_to_short_channel_id(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
			      struct short_channel_id *scid UNNEEDED)
{ fprintf(stderr, "json_to_short_channel_id called!\n"); abort(); }
/* Generated stub for json_to_short_channel_id_dir */
bool json_to_short_channel_id_dir(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
				  struct short_channel_id_dir *scidd UNNEEDED)
{ fprintf(stderr, "json_to_short_channel_id_dir called!\n"); abort(); }
/* Generated stub for json_to_txid */
bool json_to_txid(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
		  struct bitcoin_txid *txid UNNEEDED)
{ fprintf(stderr, "json_to_txid called!\n"); abort(); }
/* Generated stub for json_to_u16 */
bool json_to_u16(const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED,
                 uint16_t *num UNNEEDED)
{ fprintf(stderr, "json_to_u16 called!\n"); abort(); }
/* Generated stub for json_tok_bin_from_hex */
u8 *json_tok_bin_from_hex(const tal_t *ctx UNNEEDED, const char *buffer UNNEEDED, const jsmntok_t *tok UNNEEDED)
{ fprintf(stderr, "json_tok_bin_from_hex called!\n"); abort(); }
/* Generated stub for lease_rates_fromhex */
struct lease_rates *lease_rates_fromhex(const tal_t *ctx UNNEEDED,
					const char *hexdata UNNEEDED, size_t len UNNEEDED)
{ fprintf(stderr, "lease_rates_fromhex called!\n"); abort(); }
/* Generated stub for segwit_addr_decode */
int segwit_addr_decode(
    int* ver UNNEEDED,
    uint8_t* prog UNNEEDED,
    size_t* prog_len UNNEEDED,
    const char* hrp UNNEEDED,
    const char* addr
)
{ fprintf(stderr, "segwit_addr_decode called!\n"); abort(); }
/* Generated stub for to_canonical_invstr */
const char *to_canonical_invstr(const tal_t *ctx UNNEEDED, const char *invstring UNNEEDED)
{ fprintf(stderr, "to_canonical_invstr called!\n"); abort(); }
/* Generated stub for towire */
void towire(u8 **pptr UNNEEDED, const void *data UNNEEDED, size_t len UNNEEDED)
{ fprintf(stderr, "towire called!\n"); abort(); }
/* Generated stub for towire_bool */
void towire_bool(u8 **pptr UNNEEDED, bool v UNNEEDED)
{ fprintf(stderr, "towire_bool called!\n"); abort(); }
/* Generated stub for towire_secp256k1_ecdsa_signature */
void towire_secp256k1_ecdsa_signature(u8 **pptr UNNEEDED,
			      const secp256k1_ecdsa_signature *signature UNNEEDED)
{ fprintf(stderr, "towire_secp256k1_ecdsa_signature called!\n"); abort(); }
/* Generated stub for towire_sha256 */
void towire_sha256(u8 **pptr UNNEEDED, const struct sha256 *sha256 UNNEEDED)
{ fprintf(stderr, "towire_sha256 called!\n"); abort(); }
/* Generated stub for towire_u32 */
void towire_u32(u8 **pptr UNNEEDED, u32 v UNNEEDED)
{ fprintf(stderr, "towire_u32 called!\n"); abort(); }
/* Generated stub for towire_u64 */
void towire_u64(u8 **pptr UNNEEDED, u64 v UNNEEDED)
{ fprintf(stderr, "towire_u64 called!\n"); abort(); }
/* Generated stub for towire_u8 */
void towire_u8(u8 **pptr UNNEEDED, u8 v UNNEEDED)
{ fprintf(stderr, "towire_u8 called!\n"); abort(); }
/* Generated stub for towire_u8_array */
void towire_u8_array(u8 **pptr UNNEEDED, const u8 *arr UNNEEDED, size_t num UNNEEDED)
{ fprintf(stderr, "towire_u8_array called!\n"); abort(); }
/* AUTOGENERATED MOCKS END */

bool deprecated_apis;

static bool dump_filter(const char *key, struct json_filter *filter, u32 *depth)
{
	for (size_t i = 0; i < *depth; i++)
		printf("    ");
	printf("%s\n", key);
	(*depth)++;
	if (filter->filter_array)
		dump_filter("[]", filter->filter_array, depth);
	else
		strmap_iterate(&filter->filter_map, dump_filter, depth);
	(*depth)--;
	return true;
}

struct command {
	struct json_filter *filter;
};

struct json_filter **command_filter_ptr(struct command *cmd)
{
	return &cmd->filter;
}

int main(int argc, char *argv[])
{
	jsmntok_t *toks;
	bool valid, complete;
	const char *str;
	jsmn_parser parser;
	struct command *cmd;
	struct json_stream *js;
	u32 depth;
	size_t len;

	common_setup(argv[0]);
	cmd = tal(tmpctx, struct command);
	str = "{\"transactions\": [{\"outputs\": [{\"amount_msat\": true, \"type\": true}]}]}";
	toks = toks_alloc(cmd);
	jsmn_init(&parser);
	valid = json_parse_input(&parser, &toks, str, strlen(str), &complete);
	assert(valid);
	assert(complete);

	assert(parse_filter(cmd, "_field", str, toks) == NULL);
	assert(cmd->filter);
	depth = 0;
	dump_filter("[root]", cmd->filter, &depth);

	/* Simulate listtransactions example */
	js = new_json_stream(cmd, cmd, NULL);
	json_object_start(js, NULL);
	json_object_start(js, "result");
	json_stream_attach_filter(js, cmd->filter);

	json_array_start(js, "transactions");
	for (size_t i = 0; i < 2; i++) {
		json_object_start(js, NULL);
		json_add_num(js, "blockheight", 1);
		json_add_num(js, "txindex", 2);
		json_array_start(js, "inputs");
		for (size_t j = 0; j < 5; j++) {
			json_object_start(js, NULL);
			json_add_u32(js, "index", i+j);
			json_add_u32(js, "sequence", i+j+1);
			json_object_end(js);
		}
		json_array_end(js);

		json_array_start(js, "outputs");
		for (size_t j = 0; j < 2; j++) {
			json_object_start(js, NULL);

			json_add_u32(js, "index", i+j);
			json_add_amount_msat(js, "amount_msat", amount_msat(12));
			if (j == 0)
				json_add_string(js, "type", "sometype");
			json_add_string(js, "scriptPubKey", "00000000");
			json_object_end(js);
		}
		json_array_end(js);
		json_object_end(js);
	}
	json_array_end(js);
	str = json_stream_detach_filter(tmpctx, js);
	assert(!str);
	json_object_end(js);
	json_object_end(js);

	str = json_out_contents(js->jout, &len);
	printf("%.*s\n", (int)len, str);

	common_shutdown();
}
