#! /usr/bin/python3

import logging
import struct
import time
logger = logging.getLogger(__name__)

from counterpartylib.lib import (
    address, backend, config, exceptions, message_type, transaction, util)
from counterpartylib.lib.messages import issuance as issuance_message
from counterpartylib.lib.messages.versions import enhanced_send


def get_asset_issuer(db, asset_name):
    issuance = issuance_message.get_latest_issuance(db, asset_name)
    return issuance['issuer']


def get_levyasset_issuer(db, asset_name):
    cursor = db.cursor()
    subasset_parent, subasset_issuance = get_subasset_issuance(db, asset_name)
    if subasset_issuance and subasset_issuance['levy_type'] == 1:
        return get_asset_issuer(db, subasset_parent)
    return None


def create_levy_info(db, source, subasset_parent, subasset_issuance):
    cursor = db.cursor()
    # TODO: implement other type. ex) levy rate = 2
    if subasset_issuance['levy_type'] != 1:
        return None

    cursor.execute('''SELECT * FROM balances \
              WHERE (address = ? AND asset = ?)''', (source, subasset_parent,))
    balances = cursor.fetchall()

    # Sender doesn't have parent token.
    result = None
    if len(balances) == 0:
        # send levy token
        levy_asset = subasset_issuance['levy_asset']
        levy_number = subasset_issuance['levy_number']
        status = 'valid'
        issuer_address = get_asset_issuer(db, subasset_parent)
        if not issuer_address:
            logger.warn("Can't find parent asset [%s]" % (subasset_parent))
            return

        result = {
            'source': source,
            'destination': issuer_address,
            'levy_type': 1,  # TODO: implement rate(2)
            'levy_asset': levy_asset,
            'levy_number': levy_number,
        }
        logger.info("Levied: asset = [%s], quantity or rate = [%s]" % (levy_asset, levy_number))

    cursor.close()
    return result


def get_subasset_issuance(db, asset):
    cursor = db.cursor()
    cursor.execute('SELECT * FROM assets WHERE (asset_name = ?)', (asset,))
    assets = cursor.fetchall()
    cursor.close()

    if len(assets) == 0:
        return None, None

    subasset_parent, subasset_longname = util.parse_subasset_from_asset_name(
        assets[0]['asset_longname'])

    if subasset_longname is None:
        return None, None

    subasset_issuance = issuance_message.get_latest_issuance(db, subasset_longname)

    if not subasset_issuance:
        return None, None

    return subasset_parent, subasset_issuance


def check(db, tx, asset, memo_bytes):
    cursor = db.cursor()

    subasset_parent, subasset_issuance = get_subasset_issuance(db, asset)

    # add
    if subasset_issuance and subasset_issuance['levy_type'] == 1:
        levy_info = create_levy_info(db, tx['source'], subasset_parent, subasset_issuance)
        if levy_info:
            sql = 'insert into levies values(:tx_hash, :source, :destination, :levy_type, :levy_asset, :levy_number)'
            cursor.execute(sql, levy_info)
            logger.info('Add levy data. tx_hash = {}'.format(tx['tx_hash']))

    # # remove
    # if memo_bytes and memo_bytes.startswith('levy_'):
    #     levy_info = memo_bytes.split('_')  # levy_RYO_TXID
    #     if len(levy_info) == 3:
    #         sql = "delete from levies where tx_hash = :tx_hash"
    #         cursor.execute(sql, {'tx_hash': levy_info[2]})
    #         logger.info('Remove levy data. tx_hash = {}'.format(levy_info[2]))

    cursor.close()
