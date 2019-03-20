import getpass
import binascii
import logging
logger = logging.getLogger(__name__)
import sys
import json
import time
from decimal import Decimal as D

import bitcoin as bitcoinlib
import bitcoin.rpc as bitcoinlib_rpc
from bitcoin.core import CBlock

from counterpartylib.lib import util
from counterpartylib.lib import script
from counterpartylib.lib import config
from counterpartylib.lib import exceptions

from counterpartylib.lib.backend import indexd

MEMPOOL_CACHE_INITIALIZED = False

def sortkeypicker(keynames):
    """http://stackoverflow.com/a/1143719"""
    negate = set()
    for i, k in enumerate(keynames):
        if k[:1] == '-':
            keynames[i] = k[1:]
            negate.add(k[1:])
    def getit(adict):
       composite = [adict[k] for k in keynames]
       for i, (k, v) in enumerate(zip(keynames, composite)):
           if k in negate:
               composite[i] = -v
       return composite
    return getit

def BACKEND():
    return sys.modules['counterpartylib.lib.backend.{}'.format(config.BACKEND_NAME)]

def getblockcount():
    return BACKEND().getblockcount()

def getblockhash(blockcount):
    return BACKEND().getblockhash(blockcount)

def getblock(block_hash, verbosity=False):
    block_hex = BACKEND().getblock(block_hash, verbosity=verbosity)
    return block_hex if verbosity else CBlock.deserialize(util.unhexlify(block_hex))

def gettransaction(tx_hash):
    return BACKEND().gettransaction(tx_hash)

def getrawtransaction(tx_hash, verbose=False, skip_missing=False):
    return BACKEND().getrawtransaction(tx_hash, verbose=verbose, skip_missing=skip_missing)

def getrawtransaction_batch(txhash_list, verbose=False, skip_missing=False):
    return BACKEND().getrawtransaction_batch(txhash_list, verbose=verbose, skip_missing=skip_missing)

def sendrawtransaction(tx_hex):
    return BACKEND().sendrawtransaction(tx_hex)

def getrawmempool():
    return BACKEND().getrawmempool()

def getindexblocksbehind():
    return BACKEND().getindexblocksbehind()

def extract_addresses(txhash_list):
    return BACKEND().extract_addresses(txhash_list)

def ensure_script_pub_key_for_inputs(coins):
    txhash_set = set()
    for coin in coins:
        if 'scriptPubKey' not in coin:
            txhash_set.add(coin['txid'])

    if len(txhash_set) > 0:
        txs = BACKEND().getrawtransaction_batch(list(txhash_set), verbose=True, skip_missing=False)
        for coin in coins:
            if 'scriptPubKey' not in coin:
                # get the scriptPubKey
                txid = coin['txid']
                for vout in txs[txid]['vout']:
                    if vout['n'] == coin['vout']:
                        coin['scriptPubKey'] = vout['scriptPubKey']['hex']

    return coins


def fee_per_kb(nblocks):
    """
    :param conf_target:
    :param mode:
    :return: fee_per_kb in satoshis, or None when unable to determine
    """

    return BACKEND().fee_per_kb(nblocks)


def deserialize(tx_hex):
    return bitcoinlib.core.CTransaction.deserialize(binascii.unhexlify(tx_hex))

def serialize(ctx):
    return bitcoinlib.core.CTransaction.serialize(ctx)

def is_valid(address):
    try:
        script.validate(address)
        return True
    except script.AddressError:
        return False

def get_txhash_list(block):
    return [bitcoinlib.core.b2lx(ctx.GetHash()) for ctx in block.vtx]

def get_tx_list(block):
    raw_transactions = {}
    tx_hash_list = []

    for ctx in block.vtx:
        tx_hash = bitcoinlib.core.b2lx(ctx.GetHash())
        raw = ctx.serialize()

        tx_hash_list.append(tx_hash)
        raw_transactions[tx_hash] = bitcoinlib.core.b2x(raw)

    return (tx_hash_list, raw_transactions)

def sort_unspent_txouts(unspent, unconfirmed=False):
    # Filter out all dust amounts to avoid bloating the resultant transaction
    unspent = list(filter(lambda x: x['value'] > config.DEFAULT_MULTISIG_DUST_SIZE, unspent))
    # Sort by amount, using the largest UTXOs available
    if config.REGTEST:
        # REGTEST has a lot of coinbase inputs that can't be spent due to maturity
        # this doesn't usually happens on mainnet or testnet because most fednodes aren't mining
        unspent = sorted(unspent, key=lambda x: (x['confirmations'], x['value']), reverse=True)
    else:
        unspent = sorted(unspent, key=lambda x: x['value'], reverse=True)

    return unspent

def get_btc_supply(normalize=False):
    """returns the total supply of {} (based on what Bitcoin Core says the current block height is)""".format(config.BTC)
    block_count = getblockcount()
    blocks_remaining = block_count
    total_supply = 0
    reward = 50.0
    while blocks_remaining > 0:
        if blocks_remaining >= 210000:
            blocks_remaining -= 210000
            total_supply += 210000 * reward
            reward /= 2
        else:
            total_supply += (blocks_remaining * reward)
            blocks_remaining = 0
    return total_supply if normalize else int(total_supply * config.UNIT)

class MempoolError(Exception):
    pass

def get_unspent_txouts(source, unconfirmed=False, unspent_tx_hash=None):
    """returns a list of unspent outputs for a specific address
    @return: A list of dicts, with each entry in the dict having the following keys:
    """

    unspent = BACKEND().get_unspent_txouts(source)

    # filter by unspent_tx_hash
    if unspent_tx_hash is not None:
        unspent = list(filter(lambda x: x['txId'] == unspent_tx_hash, unspent))

    # filter unconfirmed
    if not unconfirmed:
        unspent = [utxo for utxo in unspent if utxo['confirmations'] > 0]

    # format
    for utxo in unspent:
        utxo['amount'] = float(utxo['value'] / config.UNIT)
        utxo['txid'] = utxo['txId']
        del utxo['txId']
        # do not add scriptPubKey

    return unspent

def search_raw_transactions(address, unconfirmed=True):
    return BACKEND().search_raw_transactions(address, unconfirmed)

def get_raw_transaction(tx_hash, verbose=False, skip_missing=False):
    return BACKEND().getrawtransaction(tx_hash, verbose, skip_missing)

def decode_raw_transaction(raw_tx):
    return BACKEND().decoderawtransaction(raw_tx)

def _get_miner_fee(vins, vouts):
    # vin total values - vout total values = miner fee
    current_values = sum(float(vout['value']) for vout in vouts)
    parent_address_value = 0.0
    for vin in vins:
        parent_tx = get_raw_transaction(vin['txid'], verbose=True)
        parent_vout = parent_tx['vout'][vin['vout']]
        parent_address_value = parent_address_value + float(parent_vout['value'])
    return parent_address_value - current_values

def _get_address_value(vouts, address):
    own_vouts = filter(lambda x: 'addresses' in x['scriptPubKey'] \
                    and x['scriptPubKey']['addresses'][0] == address \
                    and len(x['scriptPubKey']['addresses']) == 1 \
                    , vouts)
    return sum(float(vout['value']) for vout in own_vouts)

def _get_ryo_transaction(address, tx):
    address_value = _get_address_value(tx['vout'], address)
    ryo_tx = {}

    ryo_tx['miner_fee'] = _get_miner_fee(tx['vin'], tx['vout'])

    # value
    parent_address_value = 0
    for c_vin in tx['vin']:
        parent_tx = get_raw_transaction(c_vin['txid'], True)
        parent_vout = parent_tx['vout'][c_vin['vout']]
        if parent_vout['scriptPubKey']['addresses'][0] == address:  # TODO: [0] this hardcoding is OK ?
            parent_address_value = parent_address_value + float(parent_vout['value'])
    calc_miner_fee = ryo_tx['miner_fee'] if parent_address_value != 0 else 0
    ryo_tx['value'] = address_value - parent_address_value + calc_miner_fee

    block = getblock(tx['blockhash'], verbosity=True)
    ryo_tx['block_height'] = block['height']
    ryo_tx['time'] = tx['time']
    ryo_tx['hash'] = tx['hash']

    return ryo_tx

def get_ryo_transaction(txid):
    tx = get_raw_transaction(txid, True)
    return_tx = {}

    # block height
    block = getblock(tx['blockhash'], verbosity=True)
    return_tx['block_height'] = block['height']

    parent_tx = get_raw_transaction(tx['vin'][0]['txid'], True)
    vout_idx = tx['vin'][0]['vout']
    return_tx['source'] = parent_tx['vout'][vout_idx]['scriptPubKey']['addresses'][0]  # TODO: check this value

    return_tx['destination'] = tx['vout'][0]['scriptPubKey']['addresses'][0]  # TODO: check this value
    return_tx['total_fee'] = _get_miner_fee(tx['vin'], tx['vout'])
    return_tx['timestamp'] = tx['time']
    # status: (o.block_height) ? 'Valid' : 'Pending',

    return_tx['hash'] = txid

    return return_tx

def search_ryo_transactions(address, unconfirmed=True):
    return_txs = BACKEND().search_raw_transactions(address, unconfirmed)
    ryo_txs = []
    return_txs.sort(key=lambda x: x['time'])
    for tx in return_txs:
        ryo_txs.append(_get_ryo_transaction(address, tx))

    return ryo_txs

class UnknownPubKeyError(Exception):
    pass

def pubkeyhash_to_pubkey(pubkeyhash, provided_pubkeys=None):
    # Search provided pubkeys.
    if provided_pubkeys:
        if type(provided_pubkeys) != list:
            provided_pubkeys = [provided_pubkeys]
        for pubkey in provided_pubkeys:
            if pubkeyhash == script.pubkey_to_pubkeyhash(util.unhexlify(pubkey)):
                return pubkey

    # Search blockchain.
    raw_transactions = search_raw_transactions(pubkeyhash, unconfirmed=True)
    for tx in raw_transactions:
        for vin in tx['vin']:
            if 'coinbase' not in vin:
                scriptsig = vin['scriptSig']
                asm = scriptsig['asm'].split(' ')
                if len(asm) >= 2:
                    # catch unhexlify errs for when asm[1] isn't a pubkey (eg; for P2SH)
                    try:
                        pubkey = asm[1]
                        if pubkeyhash == script.pubkey_to_pubkeyhash(util.unhexlify(pubkey)):
                            return pubkey
                    except binascii.Error:
                        pass

    raise UnknownPubKeyError('Public key was neither provided nor published in blockchain.')


def multisig_pubkeyhashes_to_pubkeys(address, provided_pubkeys=None):
    signatures_required, pubkeyhashes, signatures_possible = script.extract_array(address)
    pubkeys = [pubkeyhash_to_pubkey(pubkeyhash, provided_pubkeys) for pubkeyhash in pubkeyhashes]
    return script.construct_array(signatures_required, pubkeys, signatures_possible)


def init_mempool_cache():
    """prime the mempool cache, so that functioning is faster...
    """
    global MEMPOOL_CACHE_INITIALIZED
    logger.debug('Initializing mempool cache...')
    start = time.time()

    mempool_txhash_list = getrawmempool()

    #with this function, don't try to load in more than BACKEND_RAW_TRANSACTIONS_CACHE_SIZE entries
    num_tx = min(len(mempool_txhash_list), config.BACKEND_RAW_TRANSACTIONS_CACHE_SIZE)
    mempool_tx = BACKEND().getrawtransaction_batch(mempool_txhash_list[:num_tx], skip_missing=True, verbose=True)

    vin_txhash_list = []
    max_remaining_num_tx = config.BACKEND_RAW_TRANSACTIONS_CACHE_SIZE - num_tx
    if max_remaining_num_tx:
        for txid in mempool_tx:
            tx = mempool_tx[txid]
            vin_txhash_list += [vin['txid'] for vin in tx['vin']]
        BACKEND().getrawtransaction_batch(vin_txhash_list[:max_remaining_num_tx], skip_missing=True, verbose=True)

    MEMPOOL_CACHE_INITIALIZED = True
    logger.info('Mempool cache initialized: {:.2f}s for {:,} transactions'.format(time.time() - start, num_tx + min(max_remaining_num_tx, len(vin_txhash_list))))


# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
