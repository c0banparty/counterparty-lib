#! /usr/bin/python3

"""
Allow simultaneous lock and transfer.
"""

from collections import namedtuple
from counterpartylib.lib import (config, util, exceptions, util, message_type)

import struct
import decimal
import json
import logging
logger = logging.getLogger(__name__)
D = decimal.Decimal


FORMAT_1 = '>QQ?'
LENGTH_1 = 8 + 8 + 1
FORMAT_2 = '>QQ??If'
LENGTH_2 = 8 + 8 + 1 + 1 + 4 + 4
SUBASSET_FORMAT = '>QQ?B'
SUBASSET_FORMAT_LENGTH = 8 + 8 + 1 + 1
FORMAT_3 = '>QQ??IfBQH'
LENGTH_3 = 8 + 8 + 1 + 1 + 4 + 4 + 1 + 8 + 2
SUBASSET_FORMAT_2 = '>QQ?BQHB'
SUBASSET_FORMAT_LENGTH_2 = 8 + 8 + 1 + 8 + 2 + 1 + 1
ID = 20
SUBASSET_ID = 21
ID_LEVY = 22
SUBASSET_ID_LEVY = 23
# NOTE: Pascal strings are used for storing descriptions for backwards‐compatibility.
LEBY_FIX = 1
LEBY_RATE = 2


def initialise(db):
    cursor = db.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS issuances(
                      tx_index INTEGER PRIMARY KEY,
                      tx_hash TEXT UNIQUE,
                      block_index INTEGER,
                      asset TEXT,
                      quantity INTEGER,
                      divisible BOOL,
                      source TEXT,
                      issuer TEXT,
                      transfer BOOL,
                      callable BOOL,
                      call_date INTEGER,
                      call_price REAL,
                      levy_type INTEGER,
                      levy_asset TEXT,
                      levy_number INTEGER,
                      description TEXT,
                      fee_paid INTEGER,
                      locked BOOL,
                      status TEXT,
                      asset_longname TEXT,
                      FOREIGN KEY (tx_index, tx_hash, block_index) REFERENCES transactions(tx_index, tx_hash, block_index))
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      block_index_idx ON issuances (block_index)
                    ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      valid_asset_idx ON issuances (asset, status)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      status_idx ON issuances (status)
                   ''')
    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      source_idx ON issuances (source)
                   ''')

    # Add asset_longname for sub-assets
    #   SQLite can’t do `ALTER TABLE IF COLUMN NOT EXISTS`.
    columns = [column['name']
               for column in cursor.execute('''PRAGMA table_info(issuances)''')]
    if 'asset_longname' not in columns:
        cursor.execute(
            '''ALTER TABLE issuances ADD COLUMN asset_longname TEXT''')

    cursor.execute('''CREATE INDEX IF NOT EXISTS
                      asset_longname_idx ON issuances (asset_longname)
                   ''')


def validate(db, source, destination, asset, quantity, divisible, callable_,
             call_date, call_price, description, subasset_parent, subasset_longname,
             block_index, levy_type, levy_asset, levy_number):
    problems = []
    fee = 0

    if asset in (config.BTC, config.XCP):
        problems.append('cannot issue {} or {}'.format(config.BTC, config.XCP))

    if call_date is None:
        call_date = 0
    if call_price is None:
        call_price = 0.0
    if description is None:
        description = ""
    if divisible is None:
        divisible = True
    if levy_type is None:
        levy_type = 0
    if levy_number is None:
        levy_number = 0
    else:
        levy_number = int(levy_number)

    if isinstance(call_price, int):
        call_price = float(call_price)
    # ^ helps especially with calls from JS‐based clients, where parseFloat(15) returns 15 (not 15.0), which json takes as an int

    if not isinstance(quantity, int):
        problems.append('quantity must be in satoshis')
    if call_date and not isinstance(call_date, int):
        problems.append('call_date must be epoch integer')
    if call_price and not isinstance(call_price, float):
        problems.append('call_price must be a float')
    if levy_type and not isinstance(levy_type, int):
        problems.append('levy_type must be epoch integer')
    if levy_number and not isinstance(levy_number, int):
        problems.append('levy_number must be epoch integer')

    if quantity < 0:
        problems.append('negative quantity')
    if call_price < 0:
        problems.append('negative call price')
    if call_date < 0:
        problems.append('negative call date')
    if LEBY_RATE < levy_type < 0:
        problems.append(
            'levy type must be in the range [0 - {}]'.format(LEBY_RATE))
    if levy_number < 0:
        problems.append('negative levy number')

    # validate exist levy asset
    if levy_type > 0 and levy_asset:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM assets WHERE asset_name = '{}'".format(levy_asset))
        issuances = cursor.fetchall()
        cursor.close()
        if len(issuances) == 0:
            problems.append('levy asset [{}] is not exist'.format(levy_asset))

    if len(problems) > 0:
        return call_date, call_price, problems, fee, description, divisible, None, None, levy_type, levy_asset, levy_number

    # Callable, or not.
    if not callable_:
        call_date = 0
        call_price = 0.0
    # Valid re-issuance?
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM issuances \
                      WHERE (status = ? AND asset = ?)
                      ORDER BY tx_index ASC''', ('valid', asset))
    issuances = cursor.fetchall()
    cursor.close()
    reissued_asset_longname = None
    if issuances:
        reissuance = True
        last_issuance = issuances[-1]
        reissued_asset_longname = last_issuance['asset_longname']
        issuance_locked = False
        if util.enabled('issuance_lock_fix'):
            for issuance in issuances:
                if issuance['locked']:
                    issuance_locked = True
                    break
        elif last_issuance['locked']:
            # before the issuance_lock_fix, only the last issuance was checked
            issuance_locked = True

        if last_issuance['issuer'] != source:
            problems.append('issued by another address')
        if bool(last_issuance['divisible']) != bool(divisible):
            problems.append('cannot change divisibility')
        if bool(last_issuance['callable']) != bool(callable_):
            problems.append('cannot change callability')
        if last_issuance['call_date'] > call_date and (call_date != 0 or (block_index < 0 and not config.TESTNET or config.REGTEST)):
            problems.append('cannot advance call date')
        if last_issuance['call_price'] > call_price:
            problems.append('cannot reduce call price')
        if issuance_locked and quantity:
            problems.append('locked asset and non‐zero quantity')
        if last_issuance['levy_type'] and int(last_issuance['levy_type']) != levy_type:
            problems.append('cannot change levy type')
    else:
        reissuance = False
        if description.lower() == 'lock':
            problems.append('cannot lock a non‐existent asset')
        if destination:
            problems.append('cannot transfer a non‐existent asset')
        if bool(divisible) and levy_type > 0:
            problems.append(
                'Cannot specify both(divisible, levy) at the same time')

    # validate parent ownership for subasset
    if subasset_longname is not None:
        parent_issuance = get_latest_issuance(db, subasset_parent)
        if parent_issuance:
            last_parent_issuance = parent_issuance
            if last_parent_issuance['issuer'] != source:
                problems.append('parent asset owned by another address')
        else:
            problems.append('parent asset not found')

    # validate subasset issuance is not a duplicate
    if subasset_longname is not None and not reissuance:
        cursor = db.cursor()
        cursor.execute('''SELECT * FROM assets \
                          WHERE (asset_longname = ?)''', (subasset_longname,))
        assets = cursor.fetchall()
        if len(assets) > 0:
            problems.append('subasset already exists')

        # validate that the actual asset is numeric
        if asset[0] != 'A':
            problems.append('a subasset must be a numeric asset')

    # Check for existence of fee funds.
    if not reissuance:
        cursor = db.cursor()
        cursor.execute('''SELECT * FROM balances \
                          WHERE (address = ? AND asset = ?)''', (source, config.XCP))
        balances = cursor.fetchall()
        cursor.close()
        fee = 88 * config.UNIT
        if fee and (not balances or balances[0]['quantity'] < fee):
            problems.append('insufficient funds XCB')

    # Protocol change.
    if not (block_index >= 0 or config.TESTNET or config.REGTEST):
        if len(description) > 42:
            problems.append('description too long')

    # For SQLite3
    call_date = min(call_date, config.MAX_INT)
    total = sum([issuance['quantity'] for issuance in issuances])
    assert isinstance(quantity, int)
    if total + quantity > config.MAX_INT:
        problems.append('total quantity overflow')

    if destination and quantity:
        problems.append('cannot issue and transfer simultaneously')

    # For SQLite3
    if util.enabled('integer_overflow_fix', block_index=block_index) and (fee > config.MAX_INT or quantity > config.MAX_INT):
        problems.append('integer overflow')

    return call_date, call_price, problems, fee, description, divisible, reissuance, reissued_asset_longname, levy_type, levy_asset, levy_number


def compose(db, source, transfer_destination, asset, quantity, divisible, description, locked, levy_type, levy_asset, levy_number):

    # Callability is deprecated, so for re‐issuances set relevant parameters
    # to old values; for first issuances, make uncallable.
    issuance = get_latest_issuance(db, asset)
    if issuance:
        last_issuance = issuance
        callable_ = last_issuance['callable']
        call_date = last_issuance['call_date']
        call_price = last_issuance['call_price']
    else:
        callable_ = False
        call_date = 0
        call_price = 0.0

    # check subasset
    subasset_parent = None
    subasset_longname = None
    if util.enabled('subassets'):  # Protocol change.
        subasset_parent, subasset_longname = util.parse_subasset_from_asset_name(
            asset)
        if subasset_longname is not None:
            # try to find an existing subasset
            sa_cursor = db.cursor()
            sa_cursor.execute('''SELECT * FROM assets \
                              WHERE (asset_longname = ?)''', (subasset_longname,))
            assets = sa_cursor.fetchall()
            sa_cursor.close()
            if len(assets) > 0:
                # this is a reissuance
                asset = assets[0]['asset_name']
            else:
                # this is a new issuance
                #   generate a random numeric asset id which will map to this subasset
                asset = util.generate_random_asset()

    problems = None
    fee = 0
    reissuance = None
    reissued_asset_longname = None

    call_date, call_price, problems, fee, description, divisible, reissuance, reissued_asset_longname, levy_type, levy_asset, levy_number = validate(
        db, source, transfer_destination, asset, quantity, divisible, callable_,
        call_date, call_price, description, subasset_parent, subasset_longname,
        util.CURRENT_BLOCK_INDEX, levy_type, levy_asset, levy_number)
    if problems:
        raise exceptions.ComposeError(problems)

    asset_id = util.generate_asset_id(asset, util.CURRENT_BLOCK_INDEX)

    # set format version info
    format = FORMAT_2
    subasset_format = SUBASSET_FORMAT
    id = ID
    subasset_id = SUBASSET_ID
    if levy_type:
        format = FORMAT_3
        subasset_format = SUBASSET_FORMAT_2
        id = ID_LEVY
        subasset_id = SUBASSET_ID_LEVY

    params = [asset_id, quantity, 1 if divisible else 0]

    if subasset_longname is None or reissuance:
        # Type 20 standard issuance FORMAT_2 >QQ??If, FORMAT_3 >QQ??IfBQH
        #   used for standard issuances and all reissuances
        data = message_type.pack(id)
        if len(description) <= 42:
            curr_format = format + '{}p'.format(len(description) + 1)
        else:
            curr_format = format + '{}s'.format(len(description))
        params.insert(0, curr_format)
        params = params + [1 if callable_ else 0,
                           call_date or 0, call_price or 0.0]
        if levy_type:
            levy_asset_id = util.generate_asset_id(
                levy_asset, util.CURRENT_BLOCK_INDEX)
            params = params + [levy_type, levy_asset_id, levy_number]
        params.append(description.encode('utf-8'))
        data += struct.pack(*params)
    else:
        # Type 21 subasset issuance SUBASSET_FORMAT >QQ?B, SUBASSET_FORMAT2 >QQ?BQHB
        #   Used only for initial subasset issuance
        # compacts a subasset name to save space
        compacted_subasset_longname = util.compact_subasset_longname(
            subasset_longname)
        compacted_subasset_length = len(compacted_subasset_longname)
        data = message_type.pack(subasset_id)
        curr_format = subasset_format + \
            '{}s'.format(compacted_subasset_length) + \
            '{}s'.format(len(description))
        params.insert(0, curr_format)
        if levy_type:
            levy_asset_id = util.generate_asset_id(
                levy_asset, util.CURRENT_BLOCK_INDEX)
            params = params + [levy_type, levy_asset_id, levy_number]
        params = params + [compacted_subasset_length,
                           compacted_subasset_longname, description.encode('utf-8')]
        data += struct.pack(*params)

    if transfer_destination:
        destination_outputs = [(transfer_destination, None)]
    else:
        destination_outputs = []
    return (source, destination_outputs, data)


class ReturnObject(object):
    pass


def convert_namedtuple_to_object(data):
    return_object = ReturnObject()
    for attribute in dir(data):
        if attribute[0] != '_':
            setattr(return_object, attribute, getattr(data, attribute))
    return return_object


def adjust_asset_data(db, tx, source_asset):
    Asset = namedtuple(
        'Asset', 'call_date call_price problems fee description divisible reissuance reissued_asset_longname levy_type levy_asset levy_number')
    tmp_asset = Asset._make(validate(
        db, tx['source'],
        tx['destination'],
        source_asset.asset,
        source_asset.quantity,
        source_asset.divisible,
        source_asset.callable_,
        source_asset.call_date,
        source_asset.call_price,
        source_asset.description,
        source_asset.subasset_parent,
        source_asset.subasset_longname,
        tx['block_index'],
        source_asset.levy_type,
        source_asset.levy_asset,
        source_asset.levy_number))
    tmp_asset = convert_namedtuple_to_object(tmp_asset)
    for attribute in dir(tmp_asset):
        if attribute[0] != '_':
            setattr(source_asset, attribute, getattr(tmp_asset, attribute))
    return source_asset


def contrunct_asset_data(tx, message, message_type_id):
    try:
        subasset_longname = None
        levy_type = None
        levy_asset_id = None
        levy_number = None

        # set format version info
        if message_type_id in (ID, SUBASSET_ID):
            format = FORMAT_2
            length = LENGTH_2
            subasset_format = SUBASSET_FORMAT
            subasset_format_length = SUBASSET_FORMAT_LENGTH
            Asset = namedtuple(
                'Asset', 'asset_id quantity divisible callable_ call_date call_price description')
            SubAsset = namedtuple(
                'SubAsset', 'asset_id quantity divisible compacted_subasset_length')
        else:
            format = FORMAT_3
            length = LENGTH_3
            subasset_format = SUBASSET_FORMAT_2
            subasset_format_length = SUBASSET_FORMAT_LENGTH_2
            Asset = namedtuple(
                'Asset', 'asset_id quantity divisible callable_ call_date call_price levy_type levy_asset_id levy_number description')
            SubAsset = namedtuple(
                'SubAsset', 'asset_id quantity divisible levy_type levy_asset_id levy_number compacted_subasset_length')

        # Sub Asset
        if message_type_id in (SUBASSET_ID, SUBASSET_ID_LEVY) :
            if not util.enabled('subassets', block_index=tx['block_index']):
                logger.warn("subassets are not enabled at block %s" %
                            tx['block_index'])
                raise exceptions.UnpackError

            # parse a subasset original issuance message
            result_asset = convert_namedtuple_to_object(SubAsset._make(
                struct.unpack(subasset_format, message[0:subasset_format_length])))
            description_length = len(
                message) - subasset_format_length - result_asset.compacted_subasset_length
            if description_length < 0:
                logger.warn("invalid subasset length: [issuance] tx [%s]: %s" % (
                    tx['tx_hash'], result_asset.compacted_subasset_length))
                raise exceptions.UnpackError
            messages_format = '>{}s{}s'.format(
                result_asset.compacted_subasset_length, description_length)
            compacted_subasset_longname, description = struct.unpack(
                messages_format, message[subasset_format_length:])
            result_asset.subasset_longname = util.expand_subasset_longname(
                compacted_subasset_longname)
            result_asset.callable_, result_asset.call_date, result_asset.call_price = False, 0, 0.0
            try:
                result_asset.description = description.decode('utf-8')
            except UnicodeDecodeError:
                result_asset.description = ''
        # Asset
        else:
            message_len = len(message) - length
            if message_len <= 42:
                curr_format = format + '{}p'.format(message_len)
            else:
                curr_format = format + '{}s'.format(message_len)
            result_asset = convert_namedtuple_to_object(Asset._make(struct.unpack(curr_format, message)))
            result_asset.call_price = round(result_asset.call_price, 6)  # TODO: arbitrary
            try:
                result_asset.description = result_asset.description.decode('utf-8')
            except UnicodeDecodeError:
                result_asset.description = ''
        try:
            result_asset.asset = util.generate_asset_name(
                result_asset.asset_id, tx['block_index'])
            if hasattr(result_asset, 'levy_asset_id'):
                if result_asset.levy_asset_id:
                    result_asset.levy_asset = util.generate_asset_name(
                        result_asset.levy_asset_id, tx['block_index'])
                else:
                    result_asset.levy_asset = config.BTC
            result_asset.status = 'valid'
        except exceptions.AssetIDError:
            result_asset.asset = None
            result_asset.levy_asset = None
            result_asset.status = 'invalid: bad asset or levy asset name'
    except exceptions.UnpackError as e:
        result_asset = ReturnObject()
        result_asset.status = 'invalid: could not unpack'

    null_set_attrs = (
        'asset_id',
        'quantity',
        'divisible',
        'callable_',
        'call_date',
        'call_price',
        'description',
        'asset_longname',
        'subasset_parent', # parse and validate the subasset from the message
        'reissuance',
        'fee',
        'subasset_longname',
        'levy_type',
        'levy_asset',
        'levy_number',
        )
    for attr in null_set_attrs:
        if not hasattr(result_asset, attr):
            setattr(result_asset, attr, None)

    return result_asset


def get_latest_issuance(db, asset_name):
    cursor = db.cursor()
    cursor.execute('''SELECT * FROM issuances \
            WHERE (status = ? AND (asset = ? OR asset_longname = ?)) \
            ORDER BY tx_index DESC''', ('valid', asset_name, asset_name))
    issuances = cursor.fetchall()
    cursor.close()
    if len(issuances) == 0:
        return None
    return issuances[0]


def parse(db, tx, message, message_type_id):
    # Unpack message.
    asset_data = contrunct_asset_data(tx, message, message_type_id)

    # Protocol change.
    if asset_data.status == 'valid' and asset_data.subasset_longname is not None:
        try:
            # ensure the subasset_longname is valid
            util.validate_subasset_longname(asset_data.subasset_longname)
            asset_data.subasset_parent, asset_data.subasset_longname = util.parse_subasset_from_asset_name(
                asset_data.subasset_longname)
        except exceptions.AssetNameError as e:
            asset_data.asset = None
            asset_data.status = 'invalid: bad subasset name'

    if asset_data.status == 'valid':
        asset_data = adjust_asset_data(db, tx, asset_data)
        if len(asset_data.problems) > 0:
            asset_data.status = 'invalid: ' + '; '.join(asset_data.problems)
        if not util.enabled('integer_overflow_fix', block_index=tx['block_index']) and 'total quantity overflow' in asset_data.problems:
            asset_data.quantity = 0

    if tx['destination']:
        asset_data.issuer = tx['destination']
        asset_data.transfer = True
        asset_data.quantity = 0
    else:
        asset_data.issuer = tx['source']
        asset_data.transfer = False

    # Debit fee.
    if asset_data.status == 'valid':
        util.debit(db, tx['source'], config.XCP, asset_data.fee,
                   action="issuance fee", event=tx['tx_hash'])

    issuance_parse_cursor = db.cursor()

    # Lock?
    asset_data.lock = False
    if asset_data.status == 'valid':
        if asset_data.description and asset_data.description.lower() == 'lock':
            asset_data.lock = True
            issuance = get_latest_issuance(asset_data.asset)
            # Use last description. (Assume previous issuance exists because tx is valid.)
            asset_data.description = issuance['description']

        if not asset_data.reissuance:
            # Add to table of assets.
            bindings = {
                'asset_id': str(asset_data.asset_id),
                'asset_name': str(asset_data.asset),
                'block_index': tx['block_index'],
                'asset_longname': asset_data.subasset_longname,
            }
            sql = 'insert into assets values(:asset_id, :asset_name, :block_index, :asset_longname)'
            issuance_parse_cursor.execute(sql, bindings)

    if asset_data.status == 'valid' and asset_data.reissuance:
        # when reissuing, add the asset_longname to the issuances table for API lookups
        asset_data.asset_longname = asset_data.reissued_asset_longname
    else:
        asset_data.asset_longname = asset_data.subasset_longname

    # Add parsed transaction to message-type–specific table.
    bindings = {
        'tx_index': tx['tx_index'],
        'tx_hash': tx['tx_hash'],
        'block_index': tx['block_index'],
        'asset': asset_data.asset,
        'quantity': asset_data.quantity,
        'divisible': asset_data.divisible,
        'source': tx['source'],
        'issuer': asset_data.issuer,
        'transfer': asset_data.transfer,
        'callable': asset_data.callable_,
        'call_date': asset_data.call_date,
        'call_price': asset_data.call_price,
        'levy_type': asset_data.levy_type,
        'levy_asset': asset_data.levy_asset,
        'levy_number': asset_data.levy_number,
        'description': asset_data.description,
        'fee_paid': asset_data.fee,
        'locked': asset_data.lock,
        'status': asset_data.status,
        'asset_longname': asset_data.asset_longname,
    }
    if "integer overflow" not in asset_data.status:
        sql = """insert into issuances values(
        :tx_index, :tx_hash, :block_index, :asset, :quantity, :divisible,
        :source, :issuer, :transfer, :callable, :call_date, :call_price,
        :levy_type, :levy_asset, :levy_number, :description, :fee_paid,
        :locked, :status, :asset_longname)"""
        issuance_parse_cursor.execute(sql, bindings)
    else:
        logger.warn("Not storing [issuance] tx [%s]: %s" %
                    (tx['tx_hash'], asset_data.status))
        logger.debug("Bindings: %s" % (json.dumps(bindings), ))

    # Credit.
    if asset_data.status == 'valid' and asset_data.quantity:
        util.credit(db, tx['source'], asset_data.asset, asset_data.quantity,
                    action="issuance", event=tx['tx_hash'])

    issuance_parse_cursor.close()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
