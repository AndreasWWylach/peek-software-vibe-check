def retry_payment(order):
    for attempt in range(3):
        try:
            return gateway.charge(order)
        except:
            pass  # swallow everything, try again
    return None
