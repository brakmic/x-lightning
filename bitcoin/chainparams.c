#include "config.h"
#include <assert.h>
#include <bitcoin/chainparams.h>
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/utils.h>

/* Version codes for BIP32 extended keys in libwally-core.
 * Stolen from wally_bip32.h in libwally-core*/
#define BIP32_VER_MAIN_PUBLIC 0x0488B21E
#define BIP32_VER_MAIN_PRIVATE 0x0488ADE4
#define BIP32_VER_TEST_PUBLIC 0x043587CF
#define BIP32_VER_TEST_PRIVATE 0x04358394
#define BIP32_VER_SIGT_PUBLIC 0x043587CF
#define BIP32_VER_SIGT_PRIVATE 0x04358394

const struct chainparams networks[] = {
    {.network_name = "deeponion",
     .onchain_hrp = "dpn",
     .lightning_hrp = "dpn",
     .bip70_name = "main",
     .genesis_blockhash = {{{.u.u8 = {0x5e, 0x7b, 0xb0, 0x6d, 0x16, 0x26, 0x29,
				      0xd1, 0xc2, 0xf7, 0x18, 0x37, 0xf1, 0x6f,
				      0x4e, 0x34, 0x07, 0x37, 0x73, 0x44, 0xab,
				      0xba, 0x0a, 0x2e, 0x4f, 0xef, 0x58, 0x94,
				      0xe2, 0x04, 0x00, 0x00}}}},
     .rpc_port = 18580,
     .ln_port = 9735,
     .cli = "DeepOnion-cli",
     .cli_args = NULL,
     .cli_min_supported_version = 150000,
     .dust_limit = {100000},
     .max_funding = AMOUNT_SAT_INIT(60 * ((1 << 24) - 1)),
     .max_payment = AMOUNT_MSAT_INIT(60 * 0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .when_lightning_became_cool = 1700000000,
     .p2pkh_version = 31,
     .p2sh_version = 78,
     .testnet = false,
     .fee_asset_tag = NULL,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_MAIN_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_MAIN_PRIVATE},
     .is_elements = false},
    {.network_name = "testnet",
     .onchain_hrp = "tdpn",
     .lightning_hrp = "tdpn",
     .bip70_name = "test",
     .genesis_blockhash = {{{.u.u8 = {0xc3, 0x40, 0xa7, 0x76, 0xc5, 0x38, 0xbe,
				      0x95, 0x4b, 0xd3, 0xb8, 0xdd, 0x43, 0xde,
				      0x6d, 0xa1, 0xf5, 0xe5, 0x09, 0x8a, 0xa9,
				      0x99, 0xa2, 0x4f, 0x43, 0x0a, 0x65, 0xdd,
				      0x50, 0x7d, 0xe4, 0xdd}}}},
     .rpc_port = 28580,
     .ln_port = 19735,
     .cli = "DeepOnion-cli",
     .cli_args = "-testnet",
     .cli_min_supported_version = 150000,
     .dust_limit = {100000},
     .max_funding = AMOUNT_SAT_INIT(60 * ((1 << 24) - 1)),
     .max_payment = AMOUNT_MSAT_INIT(60 * 0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .when_lightning_became_cool = 1700000000,
     .p2pkh_version = 111,
     .p2sh_version = 196,
     .testnet = true,
     .fee_asset_tag = NULL,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_TEST_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_TEST_PRIVATE},
     .is_elements = false},
    {.network_name = "regtest",
     .onchain_hrp = "rdpn",
     .lightning_hrp = "rdpn",
     .bip70_name = "regtest",
     .genesis_blockhash = {{{.u.u8 = {0x03, 0xab, 0x29, 0x33, 0x54, 0x9c, 0xe8,
				      0xa3, 0xf5, 0xaa, 0xc2, 0xea, 0x4d, 0x87,
				      0x01, 0x7b, 0xc9, 0x6c, 0x26, 0xd6, 0x48,
				      0x0e, 0xa9, 0x37, 0x43, 0x9a, 0x7d, 0xea,
				      0x5e, 0x04, 0x00, 0x00}}}},
     .rpc_port = 38580,
     .ln_port = 29735,
     .cli = "DeepOnion-cli",
     .cli_args = "-regtest",
     .cli_min_supported_version = 150000,
     .dust_limit = {546},
     .max_funding = AMOUNT_SAT_INIT((1 << 24) - 1),
     .max_payment = AMOUNT_MSAT_INIT(0xFFFFFFFFULL),
     .max_supply = AMOUNT_SAT_INIT(2100000000000000),
     .when_lightning_became_cool = 1,
     .p2pkh_version = 111,
     .p2sh_version = 58,
     .testnet = true,
     .fee_asset_tag = NULL,
     .bip32_key_version = {.bip32_pubkey_version = BIP32_VER_TEST_PUBLIC,
			   .bip32_privkey_version = BIP32_VER_TEST_PRIVATE},
     .is_elements = false},
};

const struct chainparams *chainparams_for_network(const char *network_name)
{
	for (size_t i = 0; i < ARRAY_SIZE(networks); i++) {
		if (streq(network_name, networks[i].network_name)) {
			return &networks[i];
		}
	}
	return NULL;
}

const struct chainparams *
chainparams_by_chainhash(const struct bitcoin_blkid *chain_hash)
{
	for (size_t i = 0; i < ARRAY_SIZE(networks); i++) {
		if (bitcoin_blkid_eq(chain_hash,
				     &networks[i].genesis_blockhash)) {
			return &networks[i];
		}
	}
	return NULL;
}

const struct chainparams *
chainparams_by_lightning_hrp(const char *lightning_hrp)
{
	for (size_t i = 0; i < ARRAY_SIZE(networks); i++) {
		if (streq(lightning_hrp, networks[i].lightning_hrp)) {
			return &networks[i];
		}
	}
	return NULL;
}

const char *chainparams_get_network_names(const tal_t *ctx)
{
	char *networks_string = tal_strdup(ctx, networks[0].network_name);
	for (size_t i = 1; i < ARRAY_SIZE(networks); ++i)
		tal_append_fmt(&networks_string, ", %s",
			       networks[i].network_name);
	return networks_string;
}

int chainparams_get_ln_port(const struct chainparams *params)
{
	assert(params);
	return params->ln_port;
}
