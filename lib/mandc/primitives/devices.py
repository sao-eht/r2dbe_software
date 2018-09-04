import os

from ..utils import TerminalMessenger

class CheckResult(object):

	@property
	def critical(self):
		return self._critical

	@property
	def description(self):
		return self._description

	@property
	def result(self):
		return self._result

	def __init__(self, desc, result, critical=False):
		self._description = desc
		self._result = result
		self._critical = critical

	def __str__(self):
		# Success get OKAY messages
		if self.result:
			return TerminalMessenger.okay(self.description)

		# Critical failure get FAIL messages
		if self.critical:
			return TerminalMessenger.fail(self.description)

		# Regular failure get WARN messages
		return TerminalMessenger.warn(self.description)

	def __nonzero__(self):
		return self._result

class CheckingDevice(object):

	CHK = None
	CHK_EQ = 1
	CHK_LT = 2
	CHK_GT = 3

	@classmethod
	def is_available(cls, identifier, tell=None, critical=True):
		"""Check if device is available."""

		# Ping to see if device available
		response = os.system("ping -c 1 " + identifier + " > /dev/null")

		# Check the result
		result =  CheckResult("{name}: {desc}".format(name=identifier, desc="is available"),
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

	def tell(self, msg):
		if self._tell is not None:
			self._tell(msg)

	def ask(self, msg, default=True):
		if self._ask is not None:
			return self._ask(msg)

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

	def do_check(self, msg, func, assrt=True, ctype=None, critical=False):
		txt = "{name}: {desc}".format(name=self.host, desc=msg)
		result = None

		# Perform the applicable test
		if ctype == self.CHK:
			# PASS on func() == True , FAIL otherwise
			result = CheckResult(txt, func(), critical=critical)
		elif ctype == self.CHK_EQ:
			# PASS on func() == assrt, FAIL otherwise
			result = CheckResult(txt, func() == assrt, critical=critical)
		elif ctype == self.CHK_LT:
			# PASS on func() < assrt, FAIL otherwise
			result = CheckResult(txt, func() < assrt, critical=critical)
		elif ctype == self.CHK_GT:
			# PASS on func() > assrt, FAIL otherwise
			result = CheckResult(txt, func() > assrt, critical=critical)

		# Tell the outcome
		self.tell(result)

		# Add outcome to results list
		self._check_results.append(result)

		# Return the result
		return result

	def do_checklist(self, checklist):
		for msg, func, assrt, ctype, critical in checklist:
			self.do_check(msg, func, assrt=assrt, ctype=ctype, critical=critical)

	def pre_config_checks(self):
		"""Do pre-configuration checks.

		Return a list of CheckResult items, one for each check.
		"""

		self.do_checklist([])

	def post_config_checks(self):
		"""Do post-configuration checks.

		Return a list of CheckResult items, one for each check.
		"""

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
