#! /usr/bin/python3
import json
import struct
import decimal
import logging
logger = logging.getLogger(__name__)

D = decimal.Decimal
from fractions import Fraction

from counterpartylib.lib import (config, exceptions, util, backend)

"""Burn {} to earn {} during a special period of time.""".format(config.BTC, config.XCP)

ID = 60

def initialise (db):
    cursor = db.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS burns(
                      tx_index INTEGER PRIMARY KEY,
                      tx_hash TEXT UNIQUE,
                      block_index INTEGER,
                      source TEXT,
                      burned INTEGER,
                      earned INTEGER,
                      status TEXT,
                      FOREIGN KEY (tx_index, tx_hash, block_index) REFERENCES transactions(tx_index, tx_hash, block_index))
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      status_idx ON burns (status)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      address_idx ON burns (source)
                   ''')

def get_ryo_balance(address):
    balance = 0
    for utxo in backend.get_unspent_txouts(address):
        balance += utxo['amount']
    return balance

def validate (db, source, destination, quantity, block_index, overburn=False, checkpossession=True):
    problems = []

    # Check destination address.
    if destination != config.UNSPENDABLE:
        problems.append('wrong destination address')

    if not isinstance(quantity, int):
        problems.append('quantity must be in satoshis')
        return problems

    if quantity < 0: problems.append('negative quantity')

    # Try to make sure that the burned funds won't go to waste.
    if block_index < config.BURN_START - 1:
        problems.append('too early')
    elif block_index > config.BURN_END:
        problems.append('too late')

    if checkpossession:
        ryo_balance = get_ryo_balance(source) * config.UNIT
        if quantity > ryo_balance - 1:  # maybe fee is under 1 RYO
            problems.append('insufficient funds. (Burn quantity = {}) > (Possassion RYO = {} - 1)'.format(quantity, ryo_balance))

    return problems

def compose (db, source, quantity, overburn=False):
    destination = config.UNSPENDABLE
    problems = validate(db, source, destination, quantity, util.CURRENT_BLOCK_INDEX, overburn=overburn)
    if problems: raise exceptions.ComposeError(problems)

    return (source, [(destination, quantity)], None)

def parse (db, tx, MAINNET_BURNS, message=None):
    burn_parse_cursor = db.cursor()

    problems = []
    status = 'valid'

    if status == 'valid':
        problems = validate(db, tx['source'], tx['destination'], tx['btc_amount'], tx['block_index'], overburn=False)
        if problems: status = 'invalid: ' + '; '.join(problems)

        if tx['btc_amount'] != None:
            sent = tx['btc_amount']
        else:
            sent = 0

    if status == 'valid':
        # Calculate quantity of XCP earned. (Maximum 1 BTC in total, ever.)
        burned = sent
        earned = burned * 880

        # Credit source address with earned XCP.
        util.credit(db, tx['source'], config.XCP, earned, action='burn', event=tx['tx_hash'])
    else:
        burned = 0
        earned = 0

    tx_index = tx['tx_index']
    tx_hash = tx['tx_hash']
    block_index = tx['block_index']
    source = tx['source']

    # Add parsed transaction to message-type–specific table.
    # TODO: store sent in table
    bindings = {
        'tx_index': tx_index,
        'tx_hash': tx_hash,
        'block_index': block_index,
        'source': source,
        'burned': burned,
        'earned': earned,
        'status': status,
    }
    if "integer overflow" not in status:
        sql = 'insert into burns values(:tx_index, :tx_hash, :block_index, :source, :burned, :earned, :status)'
        burn_parse_cursor.execute(sql, bindings)
    else:
        logger.warn("Not storing [burn] tx [%s]: %s" % (tx['tx_hash'], status))
        logger.debug("Bindings: %s" % (json.dumps(bindings), ))

    burn_parse_cursor.close()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
