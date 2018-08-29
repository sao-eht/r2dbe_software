import os

from ..utils import TerminalMessage

class CheckResult(object):

	@property
	def description(self):
		return self._description

	@property
	def result(self):
		return self._result

	def __init__(self, desc, result):
		self._description = desc
		self._result = result

	def __str__(self):
		if self.result:
			return TerminalMessage.okay(self.description)

		return TerminalMessage.fail(self.description)

class CheckingDevice(object):

	CHK = None
	CHK_EQ = 1
	CHK_LT = 2
	CHK_GT = 3

	@classmethod
	def available_check(cls, identifier):
		response = os.system("ping -c 1 " + identifier + " > /dev/null")
		return response == 0

	def __init__(self, host):
		self.host = host

	def do_check(self, msg, func, assrt=True, ctype=None):
		if ctype == self.CHK:
			# func() returns True on PASS, False on FAIL
			return CheckResult("{name}: {desc}".format(name=self.host, desc=msg),
			  func())

		if ctype == self.CHK_EQ:
			# PASS on func() == assrt, FAIL otherwise
			return CheckResult("{name}: {desc}".format(name=self.host, desc=msg),
			  func() == assrt)

		if ctype == self.CHK_LT:
			# PASS on func() < assrt, FAIL otherwise
			return CheckResult("{name}: {desc}".format(name=self.host, desc=msg),
			  func() < assrt)

		if ctype == self.CHK_GT:
			# PASS on func() > assrt, FAIL otherwise
			return CheckResult("{name}: {desc}".format(name=self.host, desc=msg),
			  func() > assrt)

	def do_checklist(self, checklist):
		resultlist = []
		for msg, func, assrt, ctype in checklist:
			resultlist.append(self.do_check(msg, func, assrt=assrt, ctype=ctype))

		return resultlist

	def pre_config_checks(self):
		return self.do_checklist([])

	def post_config_checks(self):
		return self.do_checklist([])
