import os

class CheckingDevice(object):

	@classmethod
	def available_check(cls, identifier):
		response = os.system("ping -c 1 " + identifier + " > /dev/null")
		return response == 0

	def pre_config_checks(self):
		pass

	def post_config_checks(self):
		pass
