class TerminalMessenger(object):
	OKAY = "\033[92m"
	WARN = "\033[93m"
	FAIL = "\033[91m"
	BOLD = "\033[1m"
	ENDC = "\033[0m"

	MAXLEN = 72

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

