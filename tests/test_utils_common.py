import logging
import os

from utils.common import Common


def test_setup_logger():
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)
    os.environ['LOG_LEVEL'] = 'DEBUG'
    Common.setup_logger(logger)


def test_setup_env():
    common = Common()
    common.setup_env()
