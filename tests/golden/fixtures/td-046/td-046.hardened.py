import logging

def retry_payment(order):
    for attempt in range(3):
        try:
            return gateway.charge(order)
        except gateway.TransientError as err:  # retry only transient failures
            logging.warning("charge attempt %d failed: %s", attempt + 1, err)
            continue
    raise RuntimeError("payment failed after 3 attempts")
