#!/usr/bin/env python2.7

import logging

import os.path
import sys

from traceback import format_exception, format_exception_only

from mandc import Station
from mandc.conf import DEFAULT_CONFIG_FILE
from mandc.mark6 import MARK6_MODULES
from mandc.utils import TerminalMessenger, configure_logging

_default_log_basename = os.path.extsep.join([os.path.basename(os.path.splitext(__file__)[0]), "log"])
_default_log = os.path.sep.join([os.path.expanduser("~"), "log",_default_log_basename])

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Initialise modules on Mark6")
	parser.add_argument("-c", "--config-file", dest="conf", metavar="CONFIG", default=DEFAULT_CONFIG_FILE, type=str,
	  help="backend configuration file (default is {0})".format(DEFAULT_CONFIG_FILE))
	parser.add_argument("-l", "--log-file", dest="log", metavar="FILE", type=str, default=_default_log,
	  help="write log messages to FILE in addition to stdout (default is $HOME/log/{0})".format(_default_log_basename))
	parser.add_argument("--new-msn", action="store_true", default=False,
	  help="change module MSNs")
	parser.add_argument("-v", "--verbose", action="store_true", default=False,
	  help="set logging to level DEBUG")
	parser.add_argument("-y", "--yes-all", action="store_true", default=False,
	  help="answer yes to all questions (e.g. device config overwrite)")
	args = parser.parse_args()

	# Configure logging
	logger = configure_logging(logfilename=args.log, verbose=args.verbose,
	  stdout_logger=False)

	# Configure UI
	tm = TerminalMessenger()

	# Implement yes-to-all
	ask_proxy = tm.ask
	if args.yes_all:
		ask_proxy = None

	# Parse configuration file
	station = Station.from_file(args.conf, tell=tm.tell, ask=ask_proxy,
	  ignore_device_classes=["bdc","r2dbe"])

	# Do module dismount for each backend
	for be in zip(*station.backends.items())[1]:
		try:
			tm.tell("\n----------------------------------------------\n" \
			  "Initialising modules in {m6} for {be}".format(m6=be.mark6.host, be=be))
			be.logger.info("Module initialisation")

			# Make sure user is aware of possible data loss
			if not tm.ask(
			  "About to initialise modules in {m6}. ALL DATA WILL BE ERASED. " \
			  "Do you want to continue?", exclaim=True):
				  continue

			# Mark6 needs to pass pre-config checks for this to work
			be.mark6.pre_config_checks()
			failed = 0
			for cr in be.mark6.check_results:
				if not cr.result:
					failed += 1
			if failed > 0:
				tm.tell("{m6} failed {n} pre-config checks, cannot perform initialisation".format(
				  m6=be.mark6, n=failed), exclaim=True)
				continue

			if be.mark6.compare_module_dual_status(s1="open") or \
			   be.mark6.compare_module_dual_status(s1="closed") or \
			   be.mark6.compare_module_dual_status(s1="mounted") or \
			   be.mark6.compare_module_dual_status(s1="incomplete"):
				tm.tell(
				  "  Initialisation can only be done on unmounted modules. " \
				  "Try running mark6_unconf.py first and then re-attempt initialisation.",
				  exclaim=True)
				be.logger.error("Modules are not in suitable state for initialisation")
				for m in MARK6_MODULES:
					ms = be.mark6.get_module_status(m)
					be.logger.info("Module {m} status is {s}".format(m=m, s=ms))
				continue


			for m in MARK6_MODULES:
				tm.tell("  Initialising module #{m}".format(m=m))

				# Get module status
				ms = be.mark6.get_module_status(m)
				be.logger.info("Module {m} status is {s}".format(m=m, s=ms))
				tm.tell(
				  "    - status before initialisation is {s}".format(
				  m=m, s=ms))

				# Ask user for new module serial number if needed
				msn = ms.MSN
				if args.new_msn:
					msn = tm.enter(
					  "    enter new module serial number (exactly 8 characters long)",
					  default=ms.MSN,validate=be.mark6.valid_msn)

				# Do initialisation
				tm.tell("    - initialising (this may take a few minutes)")
				if not be.mark6.mod_init(m, msn, new=args.new_msn):
					be.logger.error("Module {m} initialisation failed".format(
					  m=m))
					tm.tell("    initialisation failed".format(m=m),
					  exclaim=True)

				# Get updated module status
				ms = be.mark6.get_module_status(m)
				be.logger.info("Module {m} status is {s}".format(m=m, s=ms))
				tm.tell(
				  "    - mstatus after initialisation is {s}".format(
				  m=m, s=ms))

		except Exception as ex:
			tm.tell(
			  "An exception occurred during Mark6 {m6} module initialisation, check logfile '{lf}' for stack trace".format(
			  m6=be.mark6, lf=args.log), exclaim=True)

			# Get last exception
			exc = sys.exc_info()

			# Log occurence
			exc_str = format_exception_only(*exc[:2])
			exc_lines = format_exception(*exc)
			logger.error(
			  "Encountered an exception '{ex}' during Mark6 {m6} module initialisation of backend '{be}', traceback follows:\n{tb}".format(
			  ex=exc_str, m6=be.mark6, be=be, tb="".join(exc_lines)))
