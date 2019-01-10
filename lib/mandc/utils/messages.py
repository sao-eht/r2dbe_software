import logging
import sys

class TerminalMessenger(object):
	OKAY = "\033[92m"
	WARN = "\033[93m"
	FAIL = "\033[91m"
	BOLD = "\033[1m"
	ENDC = "\033[0m"

	MAXLEN = 94

	@classmethod
	def okay(cls, text):
		msg = ("{txt:%ds}[{okay}{bold}OK{endc}]" % cls.MAXLEN).format(
		  txt=text[:cls.MAXLEN],okay=cls.OKAY,bold=cls.BOLD,endc=cls.ENDC)
		return msg

	@classmethod
	def warn(cls, text):
		msg = ("{txt:%ds}[{warn}{bold}WARN{endc}]" % cls.MAXLEN).format(
		  txt=text[:cls.MAXLEN],warn=cls.WARN,bold=cls.BOLD,endc=cls.ENDC)
		return msg

	@classmethod
	def fail(cls, text):
		msg = ("{txt:%ds}[{fail}{bold}FAIL{endc}]" % cls.MAXLEN).format(
		  txt=text[:cls.MAXLEN],fail=cls.FAIL,bold=cls.BOLD,endc=cls.ENDC)
		return msg

	@classmethod
	def tell(cls, text):
		print text

	@classmethod
	def ask(cls, text):
		msg = "{txt} (y/n) ".format(txt=text)
		while True:
			response = raw_input(msg)
			if response.lower() == "y":
				return True
			if response.lower() == "n":
				return False

def configure_logging(logfilename=None, verbose=None, stdout_logger=True):
	# Set up root logger
	logger = logging.getLogger()
	logger.setLevel(logging.INFO)

	all_handlers = []

	# Optionally log to stdout
	stdout_handler = None
	if stdout_logger:
		stdout_handler = logging.StreamHandler(sys.stdout)
		all_handlers.append(stdout_handler)
	# Optionally log to file
	file_handler = None
	if logfilename:
		file_handler = logging.FileHandler(logfilename, mode="a")
		all_handlers.append(file_handler)
	# Add handlers
	for handler in all_handlers:
		logger.addHandler(handler)

	# Silence all katcp messages, except CRITICAL
	katcp_logger = logging.getLogger('katcp')
	katcp_logger.setLevel(logging.CRITICAL)

	# If verbose, set level to DEBUG on file, or stdout if no logging to file
	if verbose:
		# First set DEBUG on root logger
		logger.setLevel(logging.DEBUG)
		# Then revert to INFO on 0th handler (i.e. stdout)
		if stdout_handler is not None:
			stdout_handler.setLevel(logging.INFO)
		# Finally DEBUG again on 1th handler (file if it exists, otherwise stdout again)
		if file_handler is not None:
			file_handler.setLevel(logging.DEBUG)

	# Create and set formatters
	formatter = logging.Formatter('%(name)-30s: %(asctime)s : %(levelname)-8s %(message)s')
	for handler in all_handlers:
		handler.setFormatter(formatter)

	# Initial log messages
	logger.info("Started logging in {filename}".format(filename=__file__))
	if logfilename:
		logger.info("Log file is '{log}'".format(log=logfilename))

	# Return root logger
	return logger
