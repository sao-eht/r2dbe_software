#!/usr/bin/env python2.7

import logging

import os.path
import sys

from mandc.conf import BACKEND_OPTION_BDC, BACKEND_OPTION_MARK6, DEFAULT_CONFIG_FILE
from mandc import Station
from mandc.utils import TerminalMessenger, configure_logging

_default_log_basename = os.path.extsep.join([os.path.basename(os.path.splitext(__file__)[0]), "log"])
_default_log = os.path.sep.join([os.path.expanduser("~"), "log",_default_log_basename])

if __name__ == "__main__":
	import argparse

	parser = argparse.ArgumentParser(description="Set 2-bit quantization threshold",
	  epilog="Does the threshold setting for all R2DBEs, and optionally all BDCs " \
	  "in the configuration. Attenuator adjustments that increase power by more than "\
	  "10dB requires user to confirm adjustment, unless the -f option is used.")
	parser.add_argument("-c", "--config-file", dest="conf", metavar="CONFIG", default=DEFAULT_CONFIG_FILE, type=str,
	  help="backend configuration file (default is {0})".format(DEFAULT_CONFIG_FILE))
	parser.add_argument("--exclude-bdc", action="store_true", default=False,
	  help="exclude BDC attenuators adjustment to improve ADC input power level")
	parser.add_argument("-f", "--force-auto-attn", action="store_true", default=False,
	  help="do not ask permission to increase power by more than 10dB")
	parser.add_argument("-l", "--log-file", dest="log", metavar="FILE", type=str, default=_default_log,
	  help="write log messages to FILE in addition to stdout (default is $HOME/log/{0})".format(_default_log_basename))
	parser.add_argument("-v", "--verbose", action="store_true", default=False,
	  help="set logging to level DEBUG")
	args = parser.parse_args()

	# Configure logging
	logger = configure_logging(logfilename=args.log, verbose=args.verbose,
	  stdout_logger=False)

	# Configure UI
	tm = TerminalMessenger()

	# Should configuration include BDC?
	ignore_list = [BACKEND_OPTION_MARK6]
	if args.exclude_bdc:
		ignore_list.append(BACKEND_OPTION_BDC)

	# Parse configuration file
	station = Station.from_file(args.conf, tell=tm.tell, ask=tm.ask,
	  ignore_device_classes=ignore_list)

	# Do ALC for each backend
	tm.tell("\n############### Performing ALC ###############")
	for be in zip(*station.backends.items())[1]:
		be.alc(digital_only=args.exclude_bdc, use_tell=True,
		  auto_accept=args.force_auto_attn)

	tm.tell("\n############### Done performing ALC ###############")
