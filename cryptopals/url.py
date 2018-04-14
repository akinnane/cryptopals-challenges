""" A module for the needed url operations."""
import logging

logging.basicConfig(level=logging.DEBUG)


def decode_query(query):
    """Take a URL formatted query string `foo=bar&baz=qux&zap=zazzle` and

    :param query: The query string
    :returns: A python dict for the mappings
    :rtype: dict

    """
    return {
        pairs.split('=')[0]: pairs.split('=')[1]
        for pairs in query.split('&')
    }


def encode_query(query):
    remove = '&='
    return '&'.join(
        '='.join(
            [
                str(k).translate(None, remove),
                str(v).translate(None, remove),
            ]
        )
        for k, v in query.items()
    )
