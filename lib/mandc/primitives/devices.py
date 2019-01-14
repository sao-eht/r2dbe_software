import os

from ..utils import TerminalMessenger

class CheckResult(object):

	@property
	def critical(self):
		return self._critical

	@property
	def code(self):
		return self._code

	@property
	def description(self):
		return self._description

	@property
	def recommends(self):
		return self._recommends

	@property
	def result(self):
		return self._result

	@property
	def result_string(self):
		if self.result:
			return "passed"
		return "failed"

	def _make_nice_message(self):
		# Success get OKAY messages
		if self.result:
			return TerminalMessenger.okay(self.description)

		# Critical failure get FAIL messages
		if self.critical:
			return TerminalMessenger.fail(self.description)

		# Regular failure get WARN messages
		return TerminalMessenger.warn(self.description)

	def __init__(self, desc, result, critical=False, code=None, recommends=[]):
		self._description = desc
		self._result = result
		self._critical = critical
		self._code = code
		self._recommends = recommends

	def __str__(self):
		# Get nice message
		txt = self._make_nice_message()

		# Append code, if defined
		if self.code is not None:
			txt = "{txt} #{me.code:04d}".format(me=self,txt=txt)

		return txt

	def get_summary(self):
		return str(self)

	def get_full(self):
		txt = "Check #{me.code} {me.result_string}, {me.description}.".format(
		  me=self)
		if not self.result and len(self.recommends) > 0:
			txt = txt + " Recommended actions:"
			for n, r in enumerate(self.recommends):
				txt = txt + "\n   {n:2d}. {do}".format(n=1+n, do=r)

		return txt

	def __nonzero__(self):
		return self._result

class CheckingDevice(object):

	CHK = None
	CHK_EQ = 1
	CHK_LT = 2
	CHK_GT = 3

	CHECK_CODE_HIGH = 0

	@classmethod
	def is_available(cls, identifier, tell=None, critical=True):
		"""Check if device is available."""

		# Ping to see if device available
		response = os.system("ping -c 1 " + identifier + " > /dev/null")

		# Check the result
		result =  CheckResult("   - {name} {desc}".format(name=identifier, desc="should be available"),
		  response == 0, critical=critical)

		# Feedback to user, if available
		if tell is not None:
			tell(result)

		# Return the result
		return result

	def __init__(self, host, tell=None, ask=None):
		self.host = host

		# Initialize the check results list
		self._check_results = []

		# Assign callbacks for user interaction
		self._tell = tell
		self._ask = ask

	def tell(self, msg, id_me=True, **kwargs):
		if self._tell is not None:
			me = ""
			if self.host is not None and id_me:
				me = "  {me}: ".format(me=self.host)
			self._tell("{me}{msg}".format(me=me,msg=msg), **kwargs)

	def ask(self, msg, default=True, **kwargs):
		if self._ask is not None:
			return self._ask(msg, **kwargs)

		# If not ask method registered, return the default
		return default

	@property
	def check_results(self):
		"""Return generator over check results."""

		while True:

			# If no checks left, stop
			if len(self._check_results) == 0:
				break

			# Return earliest result and remove from list
			yield self._check_results.pop(0)

	def do_check(self, msg, func, assrt=True, ctype=None, critical=False,
	  code=None, recommends=[]):
		txt = "{desc}".format(desc=msg)
		result = None

		# Perform the applicable test
		if ctype == self.CHK:
			# PASS on func() == True , FAIL otherwise
			result = CheckResult(txt, func(), critical=critical, code=code,
			  recommends=recommends)
		elif ctype == self.CHK_EQ:
			# PASS on func() == assrt, FAIL otherwise
			result = CheckResult(txt, func() == assrt, critical=critical,
			  code=code, recommends=recommends)
		elif ctype == self.CHK_LT:
			# PASS on func() < assrt, FAIL otherwise
			result = CheckResult(txt, func() < assrt, critical=critical,
			  code=code, recommends=recommends)
		elif ctype == self.CHK_GT:
			# PASS on func() > assrt, FAIL otherwise
			result = CheckResult(txt, func() > assrt, critical=critical,
			  code=code, recommends=recommends)

		# Tell the outcome
		self.tell("    - {res}".format(res=result), id_me=False)

		# Log the outcome if possible
		if hasattr(self, "logger"):
			outcome = "passed" if result.result else "failed"
			critical = "ritical c" if result.critical else ""
			log = self.logger.info
			if not result.result:
				log = self.logger.warning
				if result.critical:
					log = self.logger.error
			log("C{c}heck {o}: '{d}'".format(c=critical,o=outcome,d=result.description))

		# Add outcome to results list
		self._check_results.append(result)

		# Return the result
		return result

	def do_checklist(self, checklist):
		for check in checklist:
			self.do_check(*check)

	def pre_config_checks(self):
		"""Do pre-configuration checks.

		Return a list of CheckResult items, one for each check.
		"""

		self.tell("Doing pre-config checks")

		self.do_checklist([])

	def post_config_checks(self):
		"""Do post-configuration checks.

		Return a list of CheckResult items, one for each check.
		"""

		self.tell("Doing post-config checks")

		self.do_checklist([])

	@property
	def device_config(self):
		"""Return the configuration of the actual device."""
		try:
			return self._dev
		except:
			return 0

	@property
	def object_config(self):
		"""Return the configuration of the Python object instance representing the device."""
		try:
			return self._obj
		except:
			return 1

	def config_device(self, cfg):
		"""Set the configuration of the actual device.

		Return a list of CheckResult items, one for each check.
		"""

		self.tell("Configuring device")

		self._dev = cfg

		self.do_checklist([])

	def config_object(self, cfg, tell=None, ask=None):
		"""Set the configuration of the Python object instance representing the device.

		Return a list of CheckResult items, one for each check.
		"""

		self._obj = cfg

		self.do_checklist([])

	def config_match(self, dev=None, obj=None):
		"""Compare device and object configurations.

		If dev is not None, use the given configuration instead of the current
		device configuration. If obj is not None, use the given configuration
		instead of the current object configuration.

		Keyword arguments
		-----------------
		dev -- device configuration (default None)
		obj -- object configuration (default None)

		Returns
		-------
		True if the two configurations are identical, otherwise return False.
		"""

		if dev is None:
			dev = self.device_config
		if obj is None:
			obj = self.object_config

		return dev == obj

	@property
	def device_is_configured(self):
		"""Check if device is configured."""

		try:
			_ = self._dev
		except:
			return False

		return True

	def device_matches_object(self, obj=None):
		"""Check if device is configured to match object configuration.

		If obj is not None, use the given configuration instead of the current
		object configuration.

		Keyword arguments
		-----------------
		obj -- object configuration (default None)

		Returns
		-------
		True if the device is configured and if that configuration matches the
		object configuration.
		"""

		return self.device_is_configured and self.config_match(obj=obj)
