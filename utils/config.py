'''
utility method to load the config file in a
centralized way.
'''
import json
import logging

logging.basicConfig(level=logging.INFO)


def get_config(cfg_file='opts/config.json'):
    logger = logging.getLogger(__name__)
    try:
        with open(cfg_file, 'r') as config_file:
            config = json.load(config_file)
            return config
    except Exception as e:  # pragma: no cover
        logger.error(
            "unable to read '%s' properly because: %s", cfg_file, str(e))
    return
