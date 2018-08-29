import os

class CheckingDevice(object):

	@classmethod
	def available_check(cls, identifier):
		response = os.system("ping -c 1 " + identifier + " > /dev/null")
		return response == 0

	def __init__(self, host):
		self.host = host

	def pre_config_checks(self):
		pass

	def post_config_checks(self):
		pass
