"""Variables prefixed with `DEFAULT` should be able to be overridden by
configuration file and command‐line arguments."""

UNIT = 100000000        # The same across assets.


# Versions
VERSION_MAJOR = 9
VERSION_MINOR = 56
VERSION_REVISION = 1
VERSION_STRING = str(VERSION_MAJOR) + '.' + str(VERSION_MINOR) + '.' + str(VERSION_REVISION)


# Counterparty protocol
TXTYPE_FORMAT = '>I'
SHORT_TXTYPE_FORMAT = 'B'

TWO_WEEKS = 2 * 7 * 24 * 3600
# MAX_EXPIRATION = 4 * 2016   # Two months
MAX_EXPIRATION = 65535   # over counterwallet ORDER_DEFAULT_EXPIRATION = 18000

MEMPOOL_BLOCK_HASH = 'mempool'
MEMPOOL_BLOCK_INDEX = 9999999


# SQLite3
MAX_INT = 2**63 - 1


# Bitcoin Core
OP_RETURN_MAX_SIZE = 80  # bytes


# Currency agnosticism
BTC = 'RYO'
XCP = 'XCB'

BTC_NAME = 'c0ban'
XCP_NAME = 'c0ban-party'
APP_NAME = XCP_NAME.lower()

DEFAULT_RPC_PORT_REGTEST = 24000
DEFAULT_RPC_PORT_TESTNET = 14000
DEFAULT_RPC_PORT = 4000

DEFAULT_BACKEND_PORT_REGTEST = 23882
DEFAULT_BACKEND_PORT_TESTNET = 13882
DEFAULT_BACKEND_PORT = 3882


DEFAULT_INDEXD_PORT_REGTEST = 28432
DEFAULT_INDEXD_PORT_TESTNET = 18432
DEFAULT_INDEXD_PORT = 8432


# regtest
UNSPENDABLE_REGTEST = 'mhs85bdvdYmbxwyreXLscm2qzAgcxmF7aH'
ADDRESSVERSION_REGTEST = b'\x6f'  # 111
P2SH_ADDRESSVERSION_REGTEST = b'\xc4'  # 196
PRIVATEKEY_VERSION_REGTEST = b'\xef'  # 239
MAGIC_BYTES_REGTEST = b'\xfa\xbf\xb5\xda'   # For bip-0010

# testnet
UNSPENDABLE_TESTNET = 'pcobanXXXXXXXXXXXXXXXXXXXXXXWJu7oL'
ADDRESSVERSION_TESTNET = b'\x76'  # 118
P2SH_ADDRESSVERSION_TESTNET = b'\xc6'  # 198
PRIVATEKEY_VERSION_TESTNET = b'\xee'  # 238
MAGIC_BYTES_TESTNET = b'\x83\x80\x82\x8e'   # For bip-0010

# mainnet
UNSPENDABLE_MAINNET = '8cobanXXXXXXXXXXXXXXXXXXXXXXZp2eHs'
ADDRESSVERSION_MAINNET = b'\x12'  # 18
P2SH_ADDRESSVERSION_MAINNET = b'\x1c'  # 28
PRIVATEKEY_VERSION_MAINNET = b'\x88'  # 136
MAGIC_BYTES_MAINNET = b'\x63\x30\x62\x6e'   # For bip-0010


BLOCK_FIRST_REGTEST = 0
BLOCK_FIRST_REGTEST_HASH = '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206'
BURN_START_REGTEST = 101
BURN_END_REGTEST = 9358688

BLOCK_FIRST_REGTEST_TESTCOIN = 0
BURN_START_REGTEST_TESTCOIN = 101
BURN_END_REGTEST_TESTCOIN = 9358688

BLOCK_FIRST_TESTNET_TESTCOIN = 101
BURN_START_TESTNET_TESTCOIN = 101
BURN_END_TESTNET_TESTCOIN = 9358688

BLOCK_FIRST_TESTNET = 101
BLOCK_FIRST_TESTNET_HASH = '000000001f605ec6ee8d2c0d21bf3d3ded0a31ca837acc98893876213828989d'
BURN_START_TESTNET = 101
BURN_END_TESTNET = 9358688              # Fifty years, at ten minutes per block.

BLOCK_FIRST_MAINNET_TESTCOIN = 1630117
BURN_START_MAINNET_TESTCOIN = 1630117
BURN_END_MAINNET_TESTCOIN = 9358688     # A long time.

BLOCK_FIRST_MAINNET = 1630117
BURN_START_MAINNET = 1630117
BLOCK_FIRST_MAINNET_HASH = '4703e81f99e7196d37423823de6316787e0cec76aa2748ef3a14697eda930ecf'
BURN_END_MAINNET = 9358688


# Protocol defaults
# NOTE: If the DUST_SIZE constants are changed, they MUST also be changed in counterblockd/lib/config.py as well
    # TODO: This should be updated, given their new configurability.
# TODO: The dust values should be lowered by 90%, once transactions with smaller outputs start confirming faster: <https://github.com/mastercoin-MSC/spec/issues/192>
DEFAULT_REGULAR_DUST_SIZE = 5000         # TODO: This is just a guess. I got it down to 5530 satoshis.
DEFAULT_MULTISIG_DUST_SIZE = 15000        # <https://bitcointalk.org/index.php?topic=528023.msg7469941#msg7469941>
DEFAULT_OP_RETURN_VALUE = 0
DEFAULT_FEE_PER_KB = 50000               # sane/low default, also used as minimum when estimated fee is used
ESTIMATE_FEE_PER_KB = False               # when True will use `estimatefee` from bitcoind instead of DEFAULT_FEE_PER_KB
ESTIMATE_FEE_NBLOCKS = 3

# UI defaults
DEFAULT_FEE_FRACTION_REQUIRED = .009   # 0.90%
DEFAULT_FEE_FRACTION_PROVIDED = .01    # 1.00%


DEFAULT_REQUESTS_TIMEOUT = 20   # 20 seconds
DEFAULT_RPC_BATCH_SIZE = 20     # A 1 MB block can hold about 4200 transactions.

# Custom exit codes
EXITCODE_UPDATE_REQUIRED = 5


DEFAULT_CHECK_ASSET_CONSERVATION = True

BACKEND_RAW_TRANSACTIONS_CACHE_SIZE = 20000
BACKEND_RPC_BATCH_NUM_WORKERS = 6

UNDOLOG_MAX_PAST_BLOCKS = 100 #the number of past blocks that we store undolog history

DEFAULT_UTXO_LOCKS_MAX_ADDRESSES = 1000
DEFAULT_UTXO_LOCKS_MAX_AGE = 3.0 #in seconds

ADDRESS_OPTION_REQUIRE_MEMO = 1
ADDRESS_OPTION_MAX_VALUE = ADDRESS_OPTION_REQUIRE_MEMO # Or list of all the address options

API_LIMIT_ROWS = 1000

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
