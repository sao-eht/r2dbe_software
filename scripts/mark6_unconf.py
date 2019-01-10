#!/usr/bin/env python2.7

import logging

import os.path
import sys

from traceback import format_exception, format_exception_only

from mandc import Station
from mandc.utils import TerminalMessenger, configure_logging

_default_log_basename = os.path.extsep.join([os.path.basename(os.path.splitext(__file__)[0]), "log"])
_default_log = os.path.sep.join([os.path.expanduser("~"), "log",_default_log_basename])

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Unconfigure all Mark6 devices in the configuration",
	  epilog="Delete input streams, close and unmount modules")
	parser.add_argument("-l", "--log-file", dest="log", metavar="FILE", type=str, default=_default_log,
	  help="write log messages to FILE in addition to stdout (default is $HOME/log/{0})".format(_default_log_basename))
	parser.add_argument("-v", "--verbose", action="store_true", default=False,
	  help="set logging to level DEBUG")
	parser.add_argument("-y", "--yes-all", action="store_true", default=False,
	  help="answer yes to all questions (e.g. device config overwrite)")
	parser.add_argument("conf", metavar="CONF", type=str,
	  help="backend configuration file")
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
			be.logger.info("Unconfiguring Mark6 for this backend")

			# Find Mark6 for this backend
			mark6 = be.mark6
			mark6.tell("Unconfiguring")

			# Close modules if they are open
			if mark6.compare_module_dual_status(s1="open"):
				mark6.logger.info("Found modules in open state, closing")
				if not mark6.group_close() or \
				  not mark6.compare_module_dual_status(s1="closed"):
					mark6.logger.error(
					  "Unable to put modules in closed state, trying to finish unconfigure")

			# If there are any input streams, delete them
			for input_stream in mark6.get_input_streams():
				mark6.logger.info("Deleting input_stream '{inp}'".format(
				  inp=input_stream))
				if not mark6.delete_input_stream(input_stream.label):
					mark6.tell("Input stream deletion failed", exclaim=True)
					mark6.logger.error("Unable to delete input stream '{label}'".format(
					  input_stream.label))

			# Unmount modules
			if not mark6.group_unmount() or \
			  not mark6.compare_module_dual_status(s1="unmounted"):
				mark6.tell("Module group unmount failed", exclaim=True)
				mark6.logger.error("Unable to unmount modules")

		except Exception as ex:
			tm.tell(
			  "An exception occurred during Mark6 {m6} unconfigure, check logfile '{lf}' for stack trace".format(
			  m6=mark6, lf=args.log), exclaim=True)

			# Get last exception
			exc = sys.exc_info()

			# Log occurence
			exc_str = format_exception_only(*exc[:2])
			exc_lines = format_exception(*exc)
			logger.error(
			  "Encountered an exception '{ex}' during Mark6 unconfigure of backend '{be}', traceback follows:\n{tb}".format(
			  ex=exc_str, be=be, tb="".join(exc_lines)))
