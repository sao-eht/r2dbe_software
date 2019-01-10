import logging

from socket import timeout
from telnetlib import Telnet
from time import sleep

from defines import *
from ..primitives.devices import CheckingDevice

module_logger = logging.getLogger(__name__)

class BDCConfig(object):

	def __init__(self, band):
		self._band = band

	def __eq__(self, other):
		return self.band == other.band

	def __ne__(self, other):
		return not self == other

	@property
	def band(self):
		return self._band

class BDC(CheckingDevice):

	CHECK_CODE_HIGH = 3000

	def __init__(self, host, parent_logger=module_logger, port=DEFAULT_PORT,
	  timeout_after=TIMEOUT_AFTER, **kwargs):
		super(BDC, self).__init__(host, **kwargs)

		# Set the hostname
		self.host = host

		# Start logging
		self.logger = logging.getLogger("{name}[host={host!r}]".format(
		  name=".".join((parent_logger.name,self.__class__.__name__)),
		  host=self.host,))

		# Try to establish connection
		self._connection = Telnet()
		try:
			self.connection.open(host, port, timeout=timeout_after)
		except timeout:
			self.logger.error("Timeout connecting to to {0}".format(self))
			raise RuntimeError(
			  "Timeout trying to connect to {0}. Is it up and running?".format(
			  self))

	def __repr__(self):
		return self.host

	def _send_receive(self, sout, wait=WAIT_RESPONSE):

		self.logger.debug("Sending: {msg} -->".format(msg=sout, bdc=self))

		# Send and wait for response
		self.connection.write(sout + "\n")
		sleep(wait)
		sin = self.connection.read_eager().rstrip("\n")

		self.logger.debug("Received: {msg} <--".format(msg=sin, bdc=self))

		return sin

	def _query(self, cmd, rtype="", args=[]):
		qstr = "{q}{op}{r}".format(q=cmd,op=OPERATOR_QUERY,r=rtype)
		sout = SEP.join([qstr] + [str(a) for a in args])

		# Send-and-receive
		response = self._send_receive(sout)

		# If ERROR response, we know what to say, then done
		if response.find(ERROR) == 0:
			num, msg = response.split(ERROR + " ")[1].split(": ")
			self.logger.error(
			  "Encountered error code {num} ({msg}) when sending '{cmd}'".format(
			  num=num, cmd=cmd, msg=msg))
			return ""

		# If not ERROR, assume successful result
		return response

	def _set(self, cmd, args=[]):
		sstr = "{s}{op}".format(s=cmd,op=OPERATOR_SET)
		sout = SEP.join([sstr] + [str(a) for a in args])

		# Send-and-receive
		response = self._send_receive(sout)

		# If OKAY response, done
		if response.find(OKAY) == 0:
			return True

		# If ERROR response, we know what to say, then done
		if response.find(ERROR) == 0:
			num, msg = response.split(ERROR + " ")[1].split(": ")
			self.logger.error(
			  "Encountered error code {num} ({msg}) when sending '{cmd}'".format(
			  num=num, cmd=cmd, msg=msg))
			return False

		# No clue what went wrong
		self.logger.error("Could not interpret response {resp}".format(response))

	def _valid_ctrl(self, ctrl, log_error=True):
		result = ctrl in (CTRL_BOTH, CTRL_NONE, CTRL_LOCAL, CTRL_REMOTE, CTRL_CLEAR)
		if result:
			return True

		if log_error:
			self.logger.error(
			  "Invalid control mode '{mode}', should be one of {allowed}".format(
			  mode=ctrl,allowed=", ".join(["'{0}'".format(m) for m in (
			    CTRL_BOTH, CTRL_NONE, CTRL_LOCAL, CTRL_REMOTE, CTRL_CLEAR)])))

		return False

	def _valid_pol(self, pol, log_error=True):
		result = pol in (POL_ONE, POL_ZERO)
		if result:
			return True

		if log_error:
			self.logger.error(
			  "Invalid polarization reference '{ref}', should be either '{zero}' or '{one}'".format(
			  ref=pol, one=POL_ONE, zero=POL_ZERO))

		return False

	def _valid_subband(self, subband, log_error=True):
		result = subband in (SUBBAND_LOWER, SUBBAND_UPPER)
		if result:
			return True

		if log_error:
			self.logger.error(
			  "Invalid subband reference '{ref}', should be either '{lower}' or '{upper}'".format(
			  ref=subband, one=SUBBAND_LOWER, zero=SUBBAND_UPPER))

		return False

	def _valid_band(self, band, log_error=True):
		result = band in (BAND_4TO8, BAND_5TO9)
		if result:
			return True

		if log_error:
			self.logger.error(
			  "Invalid band reference '{ref}', should be either '{fte}' or '{ftn}'".format(
			  ref=band, fte=BAND_4TO8, ftn=BAND_5TO9))

		return False

	def _validate_attenuator_level(self, level, log_error=True):
		if level >= ATTENUATOR_MIN and level <= ATTENUATOR_MAX:
			# Issue warning if level is not multiple of 0.5
			if level*10 % 5 != 0:
				self.logger.warning("Attenuation level {lvl} dB is not a multiple of 0.5 dB".format(
				  lvl=level))
			# Make sure returned level is multiple of 0.5
			return round(level*10 / 5.0) * 5.0 / 10.0

		if log_error:
			self.logger.error(
			  "Requested attenuation level {lvl} dB, outside allowable range [{mn},{mx}] dB".format(
			  lvl=level, mn=ATTENUATOR_MIN, mx=ATTENUATOR_MAX))

		return -1

	def get_identity(self):
		id_str = self._query(CMD_IDENTIFY)

		assert len(id_str) > 0

		try:
			mfc,prd,sn,ver = id_str.split(",")
			hw,fw = ver.split("_")
			hw_ver = hw.split("v")[1]
			fw_ver = fw.split("v")[1]

			self.logger.debug("Identity information is:\n" \
			  "   Manufacturer: {mfc}\n" \
			  "   Product: {prd}\n" \
			  "   Serial number: {sn}\n" \
			  "   Hardware version: {hw_ver}\n" \
			  "   Firmware version: {fw_ver}\n".format(mfc=mfc, prd=prd, sn=sn,
			  hw_ver=hw_ver, fw_ver=fw_ver))

			return mfc, prd, sn, hw_ver, fw_ver

		except:
			self.logger.error(
			  "Could not interpret identity information, response was '{r}'".format(
			  r=id_str))

		return id_str, None, None, None, None

	def set_band_4to8(self):
		return self._set(CMD_BAND, args=[BAND_4TO8_NUMBER])

	def set_band_5to9(self):
		return self._set(CMD_BAND, args=[BAND_5TO9_NUMBER])

	def set_band(self, band):
		if not self._valid_band(band):
			return False

		return self._set(CMD_BAND, args=[band])

	def is_band_4to8(self):
		nstr = self._query(CMD_BAND, rtype=QUERY_BY_NUMBER)

		assert len(nstr) > 0

		try:
			if int(nstr) == BAND_4TO8_NUMBER:
				return True
			return False
		except:
			self.logger.error("Invalid response to band query '{r}'".format(
			  r=nstr))
		return False

	def is_band_5to9(self):
		nstr = self._query(CMD_BAND, rtype=QUERY_BY_NUMBER)

		assert len(nstr) > 0

		try:
			if int(nstr) == BAND_5TO9_NUMBER:
				return True
			return False
		except:
			self.logger.error("Invalid response to band query '{r}'".format(
			  r=nstr))
		return False

	def get_band(self):
		tstr = self._query(CMD_BAND, rtype=QUERY_BY_TEXT)

		assert len(tstr) > 0

		return tstr

	def set_attenuator(self, val, pol, subband, band=None):
		# Check valid polarisation and subband reference
		if not self._valid_pol(pol) or \
		  not self._valid_subband(subband):
			  return False

		# Validate attenuator level
		level = self._validate_attenuator_level(val)
		self.logger.debug("Validated attenuator level is {lvl}".format(lvl=level))
		if level < 0:
			# Error condition
			return False

		# Make a string of it
		level_str = "%.1f" % level
		self.logger.debug("Level string is '{ls}'".format(ls=level_str))

		# Default reference in current band, just use pol-subband
		att_ref = "{p}{s}".format(p=pol,s=subband)

		# When band is specified, reference by number
		if band is not None:
			# Check valid band reference
			if not self._valid_band(band):
				return False
			att_ref = ATTENUATOR_MAP[band][pol][subband]

		# Set the level
		return self._set(CMD_ATTENUATOR, args=[att_ref, level_str])

	def get_attenuator(self, pol, subband, band=None):
		# Check valid polarisation and subband reference
		if not self._valid_pol(pol) or \
		  not self._valid_subband(subband):
			  return -1

		# Default reference in current band, just use pol-subband
		att_ref = "{p}{s}".format(p=pol,s=subband)

		# When band is specified, reference by number
		if band is not None:
			# Check valid band reference
			if not self._valid_band(band):
				return False
			att_ref = ATTENUATOR_MAP[band][pol][subband]

		# Get the level
		nstr = self._query(CMD_ATTENUATOR, args=[att_ref])

		assert len(nstr) > 0

		return float(nstr)

	def adjust_attenuator(self, delta, pol, subband, band=None):
		# Compute requested new value
		old = self.get_attenuator(pol, subband, band=band)
		new = old + delta

		# Saturate at extrema
		if new < ATTENUATOR_MIN:
			self.logger.warning(
			  "Attenuator adjustment extends below minimum ({new:.1f} < {mn}), will set to minimum".format(
			  new=new, mn=ATTENUATOR_MIN))
			new = ATTENUATOR_MIN
		if new > ATTENUATOR_MAX:
			self.logger.warning(
			  "Attenuator adjustment extends above maximum ({new:.1f} > {mx}), will set to maximum".format(
			  new=new, mx=ATTENUATOR_MAX))
			new = ATTENUATOR_MAX

		# Set level
		self.set_attenuator(new, pol, subband, band=band)

	def locked(self):
		tstr = self._query(CMD_LOCK, rtype=QUERY_BY_TEXT)

		assert len(tstr) > 0

		return tstr == LOCK_LOCKED

	def set_control_state(self, mode):
		# Check valid mode
		if not self._valid_ctrl(mode):
			return False

		# Set mode
		return self._set(CMD_CTRL, args=[mode])

	def get_control_state(self):
		tstr = self._query(CMD_CTRL)

		assert len(tstr) > 0

		return tstr

	@property
	def connection(self):
		return self._connection

	@property
	def device_is_configured(self):
		"""Check if the device is configured.

		For a BDC device this is always True
		"""

		return True

	@property
	def object_config(self):
		try:
			return BDCConfig(self._band)
		except:
			return None

	@property
	def device_config(self):
		try:
			return BDCConfig(self.get_band())
		except:
			return None

	def config_object(self, cfg):
		self._band = cfg.band

	def config_device(self, cfg):
		# Do super's config first
		super(BDC, self).config_device(cfg)

		self.set_band(cfg.band)

	def setup(self, band):

		# Create target configuration
		bc = BDCConfig(band)

		# Set the object configuration
		self.config_object(bc)

		# Check if the device config matches the object
		if self.device_matches_object():
			self.logger.info("Device configuration {name} matches specification".format(
			  name=self.host))
			if not self.ask("Device configuration for {name} matches specification. Overwrite?".format(
				  name=self.host)):
				self.logger.info("Device configuration for {name} will be left unaltered".format(
					  name=self.host))
				return
			else:
				self.logger.info("Device configuration for {name} will be overwritten".format(
				  name=self.host))

		# If device config does not match object, or ask response said to overwrite
		self.config_device(bc)

	def pre_config_checks(self):

		# Do super's pre-config checks first
		super(BDC, self).pre_config_checks()

		# Compile the checklist
		checklist = [
		  # Nothing to do here yet
		]

		# Run this class's checklist
		self.do_checklist(checklist)

	def post_config_checks(self):

		# Do super's pre-config checks first
		super(BDC, self).post_config_checks()

		# Compile the checklist
		checklist = [
		  ("band {b} should be selected".format(b=BAND_5TO9), self.is_band_5to9,
		    None, None, True,
		    self.CHECK_CODE_HIGH + 61, [
		      "Switch the BDC to the correct band",
			  ]),
		  ("LO should be {status}".format(status=LOCK_LOCKED), self.locked,
		    None, None, True,
		    self.CHECK_CODE_HIGH + 62, [
		      "Check reference frequency input to BDC",
			  ]),
		]

		# Run this class's checklist
		self.do_checklist(checklist)
