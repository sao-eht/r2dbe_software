#!/usr/bin/env python2.7

import logging

import os.path
import sys

from traceback import format_exception, format_exception_only

from mandc import Station
from mandc.conf import DEFAULT_CONFIG_FILE
from mandc.utils import TerminalMessenger, configure_logging

_default_log_basename = os.path.extsep.join([os.path.basename(os.path.splitext(__file__)[0]), "log"])
_default_log = os.path.sep.join([os.path.expanduser("~"), "log",_default_log_basename])

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Do a short recording test on Mark6s")
	parser.add_argument("-c", "--config-file", dest="conf", metavar="CONFIG", default=DEFAULT_CONFIG_FILE, type=str,
	  help="backend configuration file (default is {0})".format(DEFAULT_CONFIG_FILE))
	parser.add_argument("--duration", metavar="SECONDS", type=int, default=10,
	  help="length of time to record (default is 10)")
	parser.add_argument("-l", "--log-file", dest="log", metavar="FILE", type=str, default=_default_log,
	  help="write log messages to FILE in addition to stdout (default is $HOME/log/{0})".format(_default_log_basename))
	parser.add_argument("-m", "--mark6-list", metavar="HOST", nargs="+",
	  help="perform configuration for given list of Mark6 units only")
	parser.add_argument("-v", "--verbose", action="store_true", default=False,
	  help="set logging to level DEBUG")
	parser.add_argument("--wait", metavar="SECONDS", type=int, default=30,
	  help="delay recording by this amount of time (default is 30)")
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
		if args.mark6_list is not None and be.mark6.host not in args.mark6_list:
			tm.tell("\nSkipping {m6} recording test (not in -m option host-list)".format(
			  m6=be.mark6.host))
			continue
		try:
			tm.tell("\n----------------------------------------------\n" \
			  "Starting recording test on {m6} for {be}".format(m6=be.mark6.host, be=be))
			be.logger.info("Doing recording test")

			tm.tell(
			  "  issuing record command, then waiting for {d} seconds".format(
			  d=args.duration+args.wait))
			result = be.mark6.record_check(
			  duration=args.duration, wait=args.wait)

			if result:
				tm.tell("  {m6} recording test successful".format(m6=be.mark6.host))
			else:
				tm.tell("  {m6} recording test failed".format(m6=be.mark6.host),
				  exclaim=True)

		except Exception as ex:
			tm.tell(
			  "An exception occurred during Mark6 {m6} recording test, check logfile '{lf}' for stack trace".format(
			  m6=be.mark6, lf=args.log), exclaim=True)

			# Get last exception
			exc = sys.exc_info()

			# Log occurence
			exc_str = format_exception_only(*exc[:2])
			exc_lines = format_exception(*exc)
			logger.error(
			  "Encountered an exception '{ex}' during Mark6 {m6} recording test of backend '{be}', traceback follows:\n{tb}".format(
			  ex=exc_str, m6=be.mark6, be=be, tb="".join(exc_lines)))
