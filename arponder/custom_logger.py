import logging

def setup_logging(debug: bool, log: bool, log_file: str = None):
    level = logging.DEBUG if debug else logging.INFO

    # Define console and file handlers
    console_handler = logging.StreamHandler()
    handlers = [console_handler]

    if log:
        file_handler = logging.FileHandler(log_file)
        handlers.append(file_handler)

    # Define formats
    console_format = "%(message)s"
    file_format = "%(asctime)s.%(msecs)03d %(message)s"

    # Configure custom formatters
    console_formatter = ScreenFormatter(console_format)
    console_handler.setFormatter(console_formatter)

    if log:
        file_formatter = FileFormatter(file_format, datefmt="%H:%M:%S")
        file_handler.setFormatter(file_formatter)

    # Set up the root logger
    logging.basicConfig(level=level, handlers=handlers)

class ScreenFormatter(logging.Formatter):
    def __init__(self, fmt, datefmt=None):
        super().__init__(fmt, datefmt)

    def format(self, record):
        # Determine the symbol based on log level and message content
        if "sent a packet" in record.msg or "attempted to connect" in record.msg or "pinged you via" in record.msg:
            symbol = "[+]"
        elif record.levelno == logging.WARNING:
            symbol = "[!]"
        elif record.levelno == logging.ERROR:
            symbol = "[x]"
        else:
            symbol = "[-]"

        # Prepend the symbol for screen output
        original_msg = super().format(record)
        return f"{symbol} {original_msg}"

class FileFormatter(logging.Formatter):
    def __init__(self, fmt, datefmt=None):
        super().__init__(fmt, datefmt)

    def format(self, record):
        # Determine the symbol based on log level and message content
        if "sent a packet" in record.msg or "attempted to connect" in record.msg or "pinged you via" in record.msg:
            symbol = "[+]"
        elif record.levelno == logging.WARNING:
            symbol = "[!]"
        elif record.levelno == logging.ERROR:
            symbol = "[x]"
        else:
            symbol = "[-]"

        # Append the symbol after the timestamp for file output
        original_msg = super().format(record)
        timestamp, message = original_msg.split(" ", 1)
        return f"{timestamp} -- {symbol} {message}"
