import logging
import os

from networkml.utils.common import Common


def test_setup_logger():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    os.environ['LOG_LEVEL'] = 'DEBUG'
    Common.setup_logger(logger)


def test_setup_env():
    common = Common()
    common.setup_env()


def test_connect_rabbit():
    common = Common()
    common.connect_rabbit()


def test_get_address_info():
    common = Common()
    last_update = common.get_address_info('foo', 'bar')
    assert last_update == None
