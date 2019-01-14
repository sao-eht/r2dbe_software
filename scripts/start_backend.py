#!/usr/bin/env python2.7

import logging
import os.path
import sys

from mandc.conf import BACKEND_OPTION_BDC
from mandc import Station
from mandc.utils import TerminalMessenger, configure_logging

_default_log_basename = os.path.extsep.join([os.path.basename(os.path.splitext(__file__)[0]), "log"])
_default_log = os.path.sep.join([os.path.expanduser("~"), "log",_default_log_basename])

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Configure backend devices")
	parser.add_argument("--exclude-bdc", action="store_true", default=False,
	  help="exclude BDC from configuration")
	parser.add_argument("-l", "--log-file", dest="log", metavar="FILE", type=str, default=_default_log,
	  help="write log messages to FILE in addition to stdout (default is $HOME/log/{0})".format(_default_log_basename))
	parser.add_argument("-v", "--verbose", action="store_true", default=False,
	  help="set logging to level DEBUG")
	parser.add_argument("-y", "--yes-all", action="store_true", default=False,
	  help="answer yes to all questions (e.g. device config overwrite)")
	parser.add_argument("conf", metavar="CONFIG", type=str,
	  help="backend configuration file")
	args = parser.parse_args()

	# Configure logging
	logger = configure_logging(logfilename=args.log, verbose=args.verbose,
	  stdout_logger=False)

	# Configure UI
	tm = TerminalMessenger()

	# Should configuration include BDC?
	ignore_list = []
	if args.exclude_bdc:
		ignore_list.append(BACKEND_OPTION_BDC)

	# Implement yes-to-all
	ask_proxy = tm.ask
	if args.yes_all:
		ask_proxy = None

	# Parse configuration file
	station = Station.from_file(args.conf, tell=tm.tell, ask=ask_proxy,
	  ignore_device_classes=ignore_list)

	# Set up
	station.setup()
