import logging
import platform
import sys

from ConfigParser import RawConfigParser
from threading import Thread
from traceback import format_exception, format_exception_only
from Queue import Queue

from config import ConfigError

from conf import StationConfigParser, ValidationError, ParsingError, \
  BACKEND_OPTION_BDC, BACKEND_OPTION_R2DBE, BACKEND_OPTION_MARK6
from mark6 import Mark6
from primitives import IFSignal, SignalPath, EthRoute, ModSubGroup, CheckingDevice
from r2dbe import R2DBE_INPUTS, R2DBE_NUM_INPUTS, R2dbe
from utils import ExceptingThread
from bdc import BDC, BAND_4TO8, BAND_5TO9

module_logger = logging.getLogger(__name__)

class Backend(CheckingDevice):

	CHECK_CODE_HIGH = 2000

	def __init__(self, name, station, bdc=None, r2dbe=None, mark6=None, signal_paths=[SignalPath()],
	  parent_logger=module_logger, **kwargs):
		super(Backend, self).__init__(None, **kwargs)
		self.name = name
		self.station = station
		self.bdc = bdc
		self.r2dbe = r2dbe
		self.mark6 = mark6
		self.signal_paths = signal_paths
		self.logger = logging.getLogger("{name}[name={be}]".format(name=".".join((parent_logger.name, 
		  self.__class__.__name__)), be=self.name))
		self.logger.info(
		  "Instantiated backend with (bdc={bdc}; r2dbe={r2dbe}; mark6={mark6})".format(
		  name=self.name, bdc=self.bdc, r2dbe=self.r2dbe, mark6=self.mark6))

	def __repr__(self):
		repr_str = "[{name}|%r>>%r>>%r]" % (self.bdc,self.r2dbe,self.mark6)
		return repr_str.format(name=self.name)

	def check_link_r2dbe_mark6(self, path_n):

		# Cannot do check if no R2DBE in configuration
		if self.r2dbe is None:
			self.logger.error("Cannot check R2DBE-Mark6 link if R2DBE not part of configuration")
			return False

		# Cannot do check if no Mark6 in configuration
		if self.mark6 is None:
			self.logger.error("Cannot check R2DBE-Mark6 link if Mark6 not part of configuration")
			return False

		path = self.signal_paths[path_n]
		self.logger.debug("Check link R2DBE({me.r2dbe})<-->Mark6({me.mark6}) on path #{n}, {pth}".format(
		  me=self,n=path_n,pth=path))

		# Get receive socket on Mark6
		mark6 = self.mark6
		eth = mark6.object_config.input_streams[path_n].iface_id
		port = mark6.object_config.input_streams[path_n].portno

		# Return Mark6's check result
		return mark6.data_receive_check(eth, port)

	def check_link_bdc_r2dbe(self, path_n, wait=1.01, delta_attn_dB_abs=1.5):
		from numpy import log10
		from time import sleep
		from bdc import ATTENUATOR_MIN, ATTENUATOR_MAX

		# Cannot do check if no BDC in configuration
		if self.bdc is None:
			self.logger.error("Cannot check BDC-R2DBE link if BDC not part of configuration")
			return False

		# Cannot do check if no R2DBE in configuration
		if self.r2dbe is None:
			self.logger.error("Cannot check BDC-R2DBE link if R2DBE not part of configuration")
			return False

		path = self.signal_paths[path_n]
		self.logger.debug("Check link BDC({me.bdc})<-->R2DBE({me.r2dbe}) on path #{n}, {pth}".format(
		  me=self,n=path_n,pth=path))

		# Map signal path to BDC attenuators
		subband = self.get_bdc_band(path_n)
		pol = self.get_bdc_pol(path_n)

		# Read attenuator value
		attn_val_1_dB = self.bdc.get_attenuator(pol, subband)

		# Determine if attenuator should increase or decrease
		delta_attn_dB = delta_attn_dB_abs
		if attn_val_1_dB + delta_attn_dB > ATTENUATOR_MAX:
			delta_attn_dB = -delta_attn_dB_abs

		self.logger.debug(
		  "{me.bdc} attenuator starting value is {val0}, change will be {delta}".format(
		  me=self, val0=attn_val_1_dB, delta=delta_attn_dB))

		# Get reference time
		m0v, s0v, _ = self.r2dbe._dump_power_buffer(path_n)
		t0 = (m0v / 1000. + s0v).max()

		self.logger.debug("{me.bdc} reference time is {ref}".format(
		  me=self, ref=t0))

		# Wait for power to stabilise if needed
		sleep(wait)

		# Read power level
		m1v, s1v, p1v = self.r2dbe._dump_power_buffer(path_n)
		t1v = m1v / 1000. + s1v
		t1 = t1v.max()
		p1 = p1v[t1v > t0].mean()
		a1 = 10**(attn_val_1_dB/10.)

		self.logger.debug("{me.r2dbe} IF{n} power at time t1={t1} is {p1}".format(
		  me=self, n=path_n, t1=t1, p1=p1))

		# Adjust attenuator
		self.bdc.adjust_attenuator(delta_attn_dB, pol, subband)
		attn_val_2_dB = self.bdc.get_attenuator(pol, subband)

		# Wait for power to stabilise if needed
		sleep(wait)

		# Read power level
		m2v, s2v, p2v = self.r2dbe._dump_power_buffer(path_n)
		t2v = m2v / 1000. + s2v
		t2 = t2v.max()
		p2 = p2v[t2v > t1].mean()
		a2 = 10**(attn_val_2_dB/10.)

		self.logger.debug("{me.r2dbe} IF{n} power at time t2={t2} is {p2}".format(
		  me=self, n=path_n, t2=t2, p2=p2))

		# Reset attenuator to initial value
		self.bdc.set_attenuator(attn_val_1_dB, pol, subband)

		# Calculate delta attenuator and power
		delta_pwr = (p2 - p1)/p1
		delta_attn = (a2 - a1)/a1

		self.logger.debug(
		  "Attenuator change of {a:.1f}% caused power change of {p:.1f}%".format(
		  a=delta_attn*100, p=delta_pwr*100))

		# Change in power should be at least half the change in attenuator
		if abs(delta_pwr) < 0.5*abs(delta_attn):
			self.logger.warning(
			  "Change in power in {me.r2dbe} IF{n} is only {dp:.1f}%, " \
			  "while change in {me.bdc} {pol}{sb} is {da:.1f}%".format(
			  me=self, n=path_n, dp=delta_pwr*100, pol=pol, sb=subband,
			  da=delta_attn*100))
			return False

		return True

	def alc(self, digital_only=True, use_tell=False):
		from r2dbe import R2DBE_IDEAL_2BIT_THRESHOLD
		from numpy import log10

		# Report to stdout if requested
		if use_tell:
			do = "(digital only) " if digital_only else ""
			self.tell("\n------------------------------------\n" \
			  "Doing {do}automatic level setting for {be}".format(
			  be=self, do=do))

		# Check if devices configured
		if not self.r2dbe.device_is_configured:
			# Report to stdout if requested
			if use_tell:
				self.tell(
				  "Device {host!r} is not configured, unable to set 2-bit thresholds".format(
				  host=self.r2dbe), exclaim=True)
			# Log error and stop
			self.logger.error(
			  "Unable to set 2-bit thresholds for {host!r}, device unconfigured".format(
			  host=self.r2dbe))
			return

		# Check if valid BDC type
		if self.bdc is None:
			# Report to stdout that will do digital only, if requested
			if use_tell:
				self.tell("BDC is being ignored, will only set 2-bit threshold (no attenuator adjustments)",
				  exclaim=True)
			# Log as warning
			self.logger.warning("BDC is being ignored, not adjusting attenuators")
			# Force digital_only
			digital_only = True

		for path_n, path in enumerate(self.signal_paths):

			# Set 2-bit threshold
			self.r2dbe.set_2bit_threshold(path_n)

			# Get 2-bit threshold
			th = self.r2dbe.get_2bit_threshold(path_n)

			# Calculate recommended adjustment
			d_pwr = ((1.0 * th) / R2DBE_IDEAL_2BIT_THRESHOLD)**2
			d_pwr_dB = 10.0 * log10(d_pwr)

			self.logger.info("Recommended BDC attenuator change to {host!r} IF{n} is {d:+.1f} dB".format(
			  host=self.r2dbe, n=path_n, d=d_pwr_dB))

			# If change is less than 0.5 dB, or if no analog adjustment requested...
			if digital_only or abs(d_pwr_dB) < 0.5:
				# ...report result and move on
				self.logger.info(
				  "Set 2-bit threshold for {host!r} IF #{n} to {t}".format(
				  n=path_n, host=self.r2dbe, t=th))

				# Report to stdout if requested
				if use_tell:
					self.r2dbe.tell(
					  "Set 2-bit threshold for IF{n} to {t}, recommend power change of {d:+.1f} dB".format(
					  n=path_n, t=th, d=-d_pwr_dB))
				continue

			# Identify the BDC attenuator and adjust
			subband = self.get_bdc_band(path_n)
			pol = self.get_bdc_pol(path_n)
			self.bdc.adjust_attenuator(d_pwr_dB, pol, subband)

			# Report BDC attenuation
			att = self.bdc.get_attenuator(pol, subband)
			self.logger.info(
			  "Attenuator {p}{s} on {host} set to {v}".format(
			  p=pol, s=subband, host=self.bdc, v=att))

			# Redo 2-bit threshold
			self.r2dbe.set_2bit_threshold(path_n)

			# Get 2-bit threshold and report
			th = self.r2dbe.get_2bit_threshold(path_n)
			self.logger.info(
			  "Set 2-bit threshold for {host!r} IF{n} to {t}".format(
			  n=path_n, host=self.r2dbe, t=th))

			# Report to stdout if requested
			if use_tell:
				self.bdc.tell("Attenuator {p}{s} on {b} set to {v}".format(
				  p=pol, s=subband, b=self.bdc, v=att))
				self.r2dbe.tell("Set 2-bit threshold for IF{n} to {t}".format(
				  n=path_n, t=th))

	def get_bdc_band(self, path_n):
		from bdc import SUBBAND_LOWER as BDC_LOW, SUBBAND_UPPER as BDC_HIGH
		from primitives import SIDEBAND_LOW as PATH_LOW, SIDEBAND_HIGH as PATH_HIGH

		path = self.signal_paths[path_n]
		subband = None
		if path.ifs.bdc_sb.sb == PATH_HIGH:
			subband = BDC_HIGH
		elif path.ifs.bdc_sb.sb == PATH_LOW:
			subband = BDC_LOW

		self.logger.debug("BDC subband for path #{n} is {b}".format(
		  n=path_n, b=subband))

		return subband

	def get_bdc_pol(self, path_n):
		from bdc import POL_ZERO as BDC_LCP, POL_ONE as BDC_RCP
		from primitives import POLARIZATION_LEFT as PATH_LCP, POLARIZATION_RIGHT as PATH_RCP

		path = self.signal_paths[path_n]
		pol = None
		if path.ifs.pol.pol == PATH_RCP:
			pol = BDC_RCP
		elif path.ifs.pol.pol == PATH_LCP:
			pol = BDC_LCP

		self.logger.debug("BDC polarization for path #{n} is {x}".format(
		  n=path_n, x=pol))

		return pol

	def setup_bdc(self, aggr_check_fails=None):
		if self.bdc is None:
			self.logger.info("No BDC in configuration for this backend")
			return True

		# BDC: pre-config checks, then setup, then post-config checks
		self.bdc.pre_config_checks()
		ce_count = 0
		for cr in self.bdc.check_results:
			if not cr.result and aggr_check_fails is not None:
				aggr_check_fails[cr.code] = cr
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			self.tell("Encountered {ce} pre-config critical errors for {bdc}, aborting setup for backend {be}".format(
			  ce=ce_count, bdc=self.bdc, be=self), exclaim=True)
			return False
		self.bdc.setup(BAND_5TO9)
		self.bdc.post_config_checks()
		ce_count = 0
		for cr in self.bdc.check_results:
			if not cr.result and aggr_check_fails is not None:
				aggr_check_fails[cr.code] = cr
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			self.tell("Encountered {ce} post-config critical errors for {bdc}, aborting setup for backend {be}".format(
			  ce=ce_count, bdc=self.bdc, be=self), exclaim=True)
			return False

		return True

	def setup_r2dbe(self, aggr_check_fails=None):
		if self.r2dbe is None:
			self.logger.info("No R2DBE in configuration for this backend")
			return True

		# R2DBE: pre-config checks, then setup, then post-config checks
		self.r2dbe.pre_config_checks()
		ce_count = 0
		for cr in self.r2dbe.check_results:
			if not cr.result and aggr_check_fails is not None:
				aggr_check_fails[cr.code] = cr
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			self.tell("Encountered {ce} pre-config critical errors for {r2}, aborting setup for backend {be}".format(
			  ce=ce_count, r2=self.r2dbe, be=self), exclaim=True)
			return False
		self.r2dbe.setup(self.station, [sp.ifs for sp in self.signal_paths],
		  [sp.ethrt for sp in self.signal_paths])
		self.r2dbe.post_config_checks()
		ce_count = 0
		for cr in self.r2dbe.check_results:
			if not cr.result and aggr_check_fails is not None:
				aggr_check_fails[cr.code] = cr
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			self.tell("Encountered {ce} post-config critical errors for {r2}, aborting setup for backend {be}".format(
			  ce=ce_count, r2=self.r2dbe, be=self), exclaim=True)
			return False

		return True

	def setup_mark6(self, aggr_check_fails=None):
		if self.mark6 is None:
			self.logger.info("No Mark6 in configuration for this backend")
			return True

		# Mark6: pre-config checks, then setup, then post-config checks
		self.mark6.pre_config_checks()
		ce_count = 0
		for cr in self.mark6.check_results:
			if not cr.result and aggr_check_fails is not None:
				aggr_check_fails[cr.code] = cr
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			self.tell("Encountered {ce} pre-config critical errors for {m6}, aborting setup for backend {be}".format(
			  ce=ce_count, m6=self.mark6.host, be=self), exclaim=True)
			return False
		self.mark6.setup(self.station, [sp.ethrt for sp in self.signal_paths],
		  [sp.modsg for sp in self.signal_paths])
		self.mark6.post_config_checks()
		ce_count = 0
		for cr in self.mark6.check_results:
			if not cr.result and aggr_check_fails is not None:
				aggr_check_fails[cr.code] = cr
			if not cr.result and cr.critical:
				ce_count += 1
		if ce_count > 0:
			self.tell("Encountered {ce} post-config critical errors for {m6}, aborting setup for backend {be}".format(
			  ce=ce_count, m6=self.mark6.host, be=self), exclaim=True)
			return False

		return True

	def setup(self, aggr_check_fails=None):

		if not self.setup_bdc(aggr_check_fails=aggr_check_fails):
			return False
		if not self.setup_r2dbe(aggr_check_fails=aggr_check_fails):
			return False
		if not self.setup_mark6(aggr_check_fails=aggr_check_fails):
			return False

		return True

	def post_config_checks(self):
		from mark6 import VV_MAX_OFFSET

		# Do super's pre-config checks first
		super(Backend, self).post_config_checks()

		if self.bdc is not None and self.r2dbe is not None:
			# Link check BDC to R2DBE
			self.tell("  Check link between {me.bdc} and {me.r2dbe}".format(
			  me=self))
			# Get names of things
			subbands = [self.get_bdc_band(n) for n in range(2)]
			pols = [self.get_bdc_pol(n) for n in range(2)]
			# Compile the checklist
			checklist = [
			  ("attenuator {bdc}.{p}{s} change should reflect in {r2dbe}.IF{n}".format(
				bdc=self.bdc, p=pols[0], s=subbands[0], r2dbe=self.r2dbe, n=0),
				lambda: self.check_link_bdc_r2dbe(0), None, None, True,
				self.CHECK_CODE_HIGH + 61, []),
			  ("attenuator {bdc}.{p}{s} change should reflect in {r2dbe}.IF{n}".format(
				bdc=self.bdc, p=pols[1], s=subbands[1], r2dbe=self.r2dbe, n=1),
				lambda: self.check_link_bdc_r2dbe(1), None, None, True,
				self.CHECK_CODE_HIGH + 61, []),
			]
			# Run first part of checklist
			self.do_checklist(checklist)

			# Drain checks
			for cr in self.check_results:
				pass

		if self.r2dbe is not None and self.mark6 is not None:
			# Link check R2DBE to Mark6
			self.tell("  Check link between {me.r2dbe} and {me.mark6.host}".format(
			  me=self))
			# Get names of things
			ifaces = [self.mark6.object_config.input_streams[n].iface_id for n in range(2)]
			ports = [self.mark6.object_config.input_streams[n].portno for n in range(2)]
			# Compile the checklist
			checklist = [
			  ("VDIF from {r2dbe}.10GbE{n} should be received in {mark6}.{e}:{p}".format(
				r2dbe=self.r2dbe, n=0, mark6=self.mark6.host, e=ifaces[0], p=ports[0]),
				lambda: self.check_link_r2dbe_mark6(0), None, None, True,
				self.CHECK_CODE_HIGH + 62, []),
			  ("VDIF from {r2dbe}.10GbE{n} should be received in {mark6}.{e}:{p}".format(
				r2dbe=self.r2dbe, n=1, mark6=self.mark6.host, e=ifaces[1], p=ports[1]),
				lambda: self.check_link_r2dbe_mark6(1), None, None, True,
				self.CHECK_CODE_HIGH + 62, []),
			]
			# Run second part of checklist
			self.do_checklist(checklist)

			# Timestamp check on Mark6
			self.tell("  Check timestamps of packets received on {me.mark6.host}".format(
			  me=self))
			# Compile checklist for both paths
			_checklist = [
			  ("packets received on {e} should be on-time " \
			    "to within {off} seconds".format(m6=self.mark6.host, e=ifaces[0],
			    p=ports[0], off=VV_MAX_OFFSET),
			  lambda: self.mark6.vv_check(ifaces[0], ports[0]), None, None, True,
			  self.CHECK_CODE_HIGH + 63),
			  ("packets received on {e} should be on-time " \
			    "to within {off} seconds".format(m6=self.mark6.host, e=ifaces[1],
			    p=ports[1], off=VV_MAX_OFFSET),
			  lambda: self.mark6.vv_check(ifaces[1], ports[1]), None, None, True,
			  self.CHECK_CODE_HIGH + 63),
			]
			# Filter out paths for which link was not verified
			checklist = []
			for ii, cr in enumerate(self.check_results):
				if cr.result:
					checklist.append(_checklist[ii])
				else:
					self.tell("    Skipping on-time check for {e}, no link established".format(
					  e=ifaces[ii]), exclaim=True)
			# Run third part of checklist
			self.do_checklist(checklist)

class Station(CheckingDevice):

	CHECK_CODE_HIGH = 1000

	def __init__(self, host, station, backends, parent_logger=module_logger, **kwargs):
		super(Station, self).__init__(host, **kwargs)
		self.station = station
		self.backends = backends
		self.logger = logging.getLogger("{name}[station={station}]".format(name=".".join((parent_logger.name, 
		  self.__class__.__name__)), station=self.station))
		self.logger.info("Configured station with backends [{be_list}]".format(
		  station=self.station, be_list=", ".join(["{be!r}".format(be=be) for be in self.backends.keys()])))

	@classmethod
	def from_file(cls, filename, tell=None, ask=None, ignore_device_classes=[]):
		# Create a parser
		scp = StationConfigParser()

		# Read the specified file (includes parsing checks)
		if tell is not None:
			tell("############### Processing configuration {fn} ###############\n".format(fn=filename))
		try:
			if len(scp.read(filename)) < 1:
				module_logger.error("Unable to read station configuration file '{0}'".format(filename))
				raise RuntimeError("Unable to read station configuration file")
		except ParsingError as pe:
			module_logger.error("{cls} raised {err} with {count} errors: {msg}".format(cls=scp.__class__.__name__,
			  err=pe.__class__.__name__, msg=str(pe), count=len(pe.errors)))
			raise pe
		except ConfigError as ce:
			module_logger.error("{cls} raised {err}: {msg}".format(cls=scp.__class__.__name__,
			  err=ce.__class__.__name__, msg=str(ce)))
			raise ce

		# Validate the configuration
		try:
			scp.validate(ignore_device_classes=ignore_device_classes)
		except ValidationError as ve:
			module_logger.error("{cls} raised {err} with {count} errors: {msg}".format(cls=scp.__class__.__name__,
			  err=ve.__class__.__name__, msg=str(ve), count=ve.count))
			raise ve

		# If we reach this point, we can assume the config should be applicable
		station = scp.station
		backend_list = scp.backends

		# Do availability checks
		avail_backends = []
		for be in backend_list:

			if tell is not None:
				tell("\n----------------------------------------------\n" \
				  "Check all devices referenced in {be} available:".format(be=be))
			avail = True

			if BACKEND_OPTION_BDC not in ignore_device_classes:
				bdc_id = scp.backend_bdc(be)
				if not BDC.is_available(bdc_id, tell=tell):
					module_logger.error("Backend device {name} is not available.".format(name=bdc_id))
					avail = False
				# Only dual-band BDCs supported for now
				_bdc = BDC(bdc_id)
				if not _bdc.is_dual_band:
					tell("BDC {name} is single-band (only dual-band units supported), ignoring this device".format(
					  name=_bdc.host), exclaim=True)
					module_logger.warning("BDC {name} is not-dual, will not be configured".format(
					  name=_bdc.host))
					ignore_device_classes.append(BACKEND_OPTION_BDC)

			if BACKEND_OPTION_R2DBE not in ignore_device_classes:
				r2dbe_id = scp.backend_r2dbe(be)
				if not R2dbe.is_available(r2dbe_id, tell=tell):
					module_logger.error("Backend device {name} is not available.".format(name=r2dbe_id))
					avail = False

			if BACKEND_OPTION_MARK6 not in ignore_device_classes:
				mark6_id = scp.backend_mark6(be)
				if not Mark6.is_available(mark6_id, tell=tell):
					module_logger.error("Backend device {name} is not available.".format(name=mark6_id))
					avail = False

			if avail:
				if tell is not None:
					tell("All devices available for {be}".format(be=be))
				avail_backends.append(be)
			else:
				if tell is not None:
					tell("One or more devices unavailable for {be}, skipping this signal path".format(be=be), exclaim=True)

		# There needs to be at least one available backend
		if len(avail_backends) < 1:
			raise RuntimeError("There are not enough backend devices available for a complete signal path")

		backends = {}
		for be in avail_backends:

			bdc = None
			if BACKEND_OPTION_BDC not in ignore_device_classes:
				bdc_id = scp.backend_bdc(be)
				bdc = BDC(bdc_id, tell=tell, ask=ask)
			r2dbe = None
			if BACKEND_OPTION_R2DBE not in ignore_device_classes:
				r2dbe_id = scp.backend_r2dbe(be)
				r2dbe = R2dbe(r2dbe_id, tell=tell, ask=ask)
			mark6 = None
			if BACKEND_OPTION_MARK6 not in ignore_device_classes:
				mark6_id = scp.backend_mark6(be)
				mark6 = Mark6(mark6_id, tell=tell, ask=ask)

			signal_paths = []
			for inp in R2DBE_INPUTS:
				# Analog input
				pol, rx_sb, bdc_sb = scp.backend_if_pol_rx_bdc(be, inp)
				ifs = IFSignal(receiver_sideband=rx_sb, blockdownconverter_sideband=bdc_sb, polarization=pol)
				eth_rt = None
				mods = None
				if mark6 is not None:
					# Ethernet routing
					mk6_iface_name = scp.backend_if_iface(be, inp)
					mac, ip = mark6.get_iface_mac_ip(mk6_iface_name)
					eth_rt = R2dbe.make_default_route_from_destination(mac, ip)
					# Module
					mods = scp.backend_if_modsubgroup(be, inp)
				# Create signal path
				signal_paths.append(SignalPath(if_signal=ifs, eth_route=eth_rt, mod_subgroup=mods))

			# Instantiate backend and add
			backends[be] = Backend(be, station, bdc=bdc, r2dbe=r2dbe, mark6=mark6,
			  signal_paths=signal_paths, tell=tell, ask=ask)

		return cls(platform.node(), station, backends, tell=tell, ask=ask)

	def setup(self):
		# If no user-input required, start backends in parallel threads
		if self.ask is None:
			# Initialize queue to keep possible exceptions
			exc_queue = Queue()

			threads = [ExceptingThread(exc_queue, target=be.setup, name=be.name)
			  for be in zip(*self.backends.items())[1]]
			[th.start() for th in threads]
			[th.join() for th in threads]

			# Check if any of the threads encountered an exception
			num_errors = 0
			while not exc_queue.empty():
				num_errors += 1
				name, exc = exc_queue.get_nowait()
				exc_str = format_exception_only(*exc[:2])
				self.logger.critical(
				  "An exception occurred during setup of backend '{be}', traceback follows:\n{tb}".format(
				  be=name, tb="".join(exc_lines)))

			# If any errors encountered, raise exception
			if num_errors > 0:
				raise RuntimeError("{0} backend(s) failed setup".format(num_errors))

		# If user-input required, then backends need setting up in series
		else:
			failed_checks = {}
			self.tell("\n############### Configuring backend devices ###############", id_me=False)
			for be in zip(*self.backends.items())[1]:
				try:
					self.tell("\n----------------------------\n" \
					  "Configuring devices for {be}:".format(be=be), id_me=False)

					# Do pre-config checks
					be.pre_config_checks()

					# Do setup
					if not be.setup(aggr_check_fails=failed_checks):
						continue

					self.tell("\nDoing post-config checks for {be}:".format(be=be),
					  id_me=False)

					# Do post-config checks
					be.post_config_checks()
				except Exception as ex:

					self.tell(
					  "An exception occurred during setup of backend '{be}'".format(
					  be=be), exclaim=True)

					# Get last exception
					exc = sys.exc_info()

					# Log occurence
					exc_str = format_exception_only(*exc[:2])
					exc_lines = format_exception(*exc)
					self.logger.error(
					  "Encountered an exception '{ex}' during setup of backend '{be}', traceback follows:\n{tb}".format(
					  ex=exc_str, be=be, tb="".join(exc_lines)))

			# vvv THIS vvv doesn't work yet
			#~ # Summary of failed checks and recommended remedial actions
			#~ for code, check_result in failed_checks.items():
				#~ if self.tell is not None:
					#~ self.tell(check_result.get_full())
			# ^^^ THIS ^^^ doesn't work yet
