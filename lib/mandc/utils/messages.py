import logging
import sys

class TerminalMessenger(object):
	OKAY = "\033[92m"
	WARN = "\033[93m"
	FAIL = "\033[91m"
	BOLD = "\033[1m"
	ENDC = "\033[0m"

	MAXLEN = 80

	@classmethod
	def okay(cls, text):
		msg = ("{txt:%ds}  [{okay}{bold}OK{endc}]" % cls.MAXLEN).format(
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
	def tell(cls, text, exclaim=False):
		if exclaim:
			text = "{red}{bold}{txt}{endc}".format(
			  red=cls.FAIL,bold=cls.BOLD,txt=text,endc=cls.ENDC)
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

	@classmethod
	def select(cls, text_pre_opt, opt_dict, default_key=None,
	  text_post_opt="Please enter your selection [%s]: "):

		# Make text for option list
		text_opt = "\n".join([
		  "  [{key}] {val}".format(key=k, val=v) for k,v in opt_dict.items()
		])

		# Compile option list
		text_opt_list = "[]"
		if len(opt_dict.keys()) < 6:
			text_opt_list = ",".join([str(k) for k in opt_dict.keys()])
		else:
			text_opt_list = "{o1}, ..., {oN}".format(o1=opt_dict.keys()[0],
			  oN = opt_dict.keys()[-1])

		# Insert option list in post-option text
		text_post_opt = text_post_opt % text_opt_list

		# Compile full message and print
		msg = "{pre}\n{opt}".format(pre=text_pre_opt, opt=text_opt)
		print msg

		# Ask selection and get reponse
		while True:
			response = raw_input(text_post_opt)

			# Check default
			if default_key is not None:
				if len(response) == 0:
					return default_key

			if response in [str(k) for k in opt_dict.keys()]:
				return response
			else:
				print "Invalid selection"

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
