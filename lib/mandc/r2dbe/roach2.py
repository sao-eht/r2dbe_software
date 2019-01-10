import logging
import socket

from datetime import datetime, timedelta
from functools import partial
from numpy import arange, array, count_nonzero, int8, nonzero, sqrt, roll, uint32, uint64, zeros
from struct import pack, unpack
from telnetlib import Telnet
from time import ctime, sleep

import adc5g

from corr.katcp_wrapper import FpgaClient
from corr.snap import snapshots_get

import adc
from ..primitives.base import IFSignal, EthEntity, EthRoute, IPAddress, MACAddress, Port
from ..primitives.devices import CheckingDevice
from defines import *
from ..data import VDIFTime

module_logger = logging.getLogger(__name__)

def format_bitcode_version(rcs):
	if "app_last_modified" in rcs.keys():
		return "compiled {0}".format(ctime(rcs["app_last_modified"]))
	if "app_rcs_type" in rcs.keys():
		if rcs["app_rcs_type"] == "git" and "app_rev" in rcs.keys():
			dirty_suffix = "-dirty" if "app_dirty" in rcs.keys() and rcs["app_dirty"] else ""
			return "git hash {0:07x}{1}".format(rcs["app_rev"], dirty_suffix)
	return "unknown"

class R2dbeConfig(object):

	def __init__(self, station, input0, input1, output0, output1):
		self._station = station
		self._inputs = [input0, input1]
		self._outputs = [output0, output1]

	@property
	def station(self):
		return self._station

	@property
	def inputs(self):
		return self._inputs

	@property
	def outputs(self):
		return self._outputs

	def __eq__(self, other):
		if self.station != other.station:
			return False
		ours = self.inputs
		theirs = self.inputs
		for o,t in zip(ours, theirs):
			if o != t:
				return False
		ours = self.outputs
		theirs = self.outputs
		for o,t in zip(ours, theirs):
			if o != t:
				return False
		return True

	def __ne__(self, other):
		return not self == other

	def __str__(self):
		return "Station: {rc.station}\n Inputs: {rc.inputs}\nOutputs: {rc.outputs}".format(rc=self)

class Roach2(CheckingDevice):

	def __init__(self, host, parent_logger=module_logger, retry_snaps=3, **kwargs):
		super(Roach2, self).__init__(host, **kwargs)
		self.logger = logging.getLogger("{name}[host={host!r}]".format(name=".".join((parent_logger.name, 
		  self.__class__.__name__)), host=self.host,))

		# Set number of retries in case snapshot read fails
		self._retry_snaps = retry_snaps

		# connect to ROACH2
		if self.host:
			self._connect()

	def _connect(self):
		self.roach2 = FpgaClient(self.host)
		if not self.roach2.wait_connected(timeout=5):
			raise RuntimeError("Timeout trying to connect to {0}. Is it up and running?".format(self.roach2.host))

	def _program(self, bitcode):
		try:
			self.roach2.progdev(bitcode)
		except RuntimeError as re:
			self.logger.critical("Failed to program {roach2!r} with bitcode {code!r}. Is the BOF file installed?".format(
			  roach2=self.host, code=bitcode))
			raise re
		return format_bitcode_version(self.roach2.get_rcs())

	def _read_int(self, name):
		value = self.roach2.read_int(name)
		self.logger.debug("read_int: {0} --> 0x{1:08x}".format(name, value))
		return value

	def _read_uint(self, name):
		value = self.roach2.read_uint(name)
		self.logger.debug("read_uint: {0} --> 0x{1:08x}".format(name, value))
		return value

	def _write_int(self, name, value):
		self.roach2.write_int(name, value)
		self.logger.debug("write_int: {0} <-- 0x{1:08x}".format(name, value))

	def _read_snap(self, names):
		tries = 0
		while True:
			try:
				snaps = snapshots_get([self.roach2] * len(names), names, man_trig=True)
				return snaps
			except RuntimeError as runtime_error:
				self.logger.error(
				  "Caught exception while attempting to read snapshots {names}, retrying ({more} tries left)".format(
				  names=names, more=self._retry_snaps-tries))
				tries += 1
				if tries >= self._retry_snaps:
					self.logger.critical("Could not read snapshot, exiting")
					raise runtime_error

	def _katcp_command(self, msg, *args):
		try:
			# Establish connection and read all there is
			tsesh = Telnet(self.host, KATCP_TELNET_PORT, timeout=5)
			_ = tsesh.read_very_eager()

			# Write the message
			snd = KATCP_REQUEST_CHR + msg + " ".join([str(a) for a in args]) + "\n"
			tsesh.write(snd)

			# Give tcpborphserver3 time to think about it
			sleep(0.5)

			# Read the response
			rsp = tsesh.read_very_eager()
			#~ rsp = '#fpga ready\n#log info 1795148 raw fpga\\_programmed,\\_mapped\\_with\\_r2dbe_rev2_v1.1.bof\\_and\\_meta\\_ready\n!fpgastatus ok\n'
			if rsp == "":
				return False, {"error":"no\_data"}, {}

			# Build the return structure
			meta = {}
			reply = {}
			lines = rsp.split("\n")
			for l in lines:
				if len(l) == 0:
					continue

				# Decide whether to put in meta or response, or ignore
				_d = None
				if l[0] == KATCP_META_CHR:
					_d = meta
				elif l[0] == KATCP_RESPONSE_CHR:
					_d = reply
				else:
					continue

				# Add / append key
				words = l.split(" ")
				key = words[0][1:]
				args = tuple(words[1:])
				if key in _d.keys():
					_d[key].append(args)
				else:
					_d[key] = [args]

			return True, reply, meta

			# Close the connection
			tsesh.close()

		except socket.timeout as to:
			self.logger.error("Timeout when trying to connect to {roach2!r} via telnet on port {portno}".format(
			  roach2=self.host, portno=KATCP_TELNET_PORT))

			return False, {"error":"timeout"}, {}

	def _fpga_programmed(self):
		"""Check if the FPGA is programmed."""

		# Get FPGA status
		res, reply, meta = self._katcp_command("fpgastatus")
		if not res:
			self.logger.error("Could not check if FPGA in {roach2!r} is programmed".format(
			  roach2=self.host))
			return False

		# Perhaps only one condition sufficient, but check both
		if ("ok",) in reply["fpgastatus"] and ("ready",) in meta["fpga"]:
			return True

		# In all other cases return False
		return False

	def pre_config_checks(self):

		# Do super's pre-config checks first
		super(Roach2, self).pre_config_checks()

		# Compile the checklist
		checklist = []

		# Run this class's checklist
		self.do_checklist(checklist)

	def post_config_checks(self):

		# Do super's pre-config checks first
		super(Roach2, self).post_config_checks()

		# Compile the checklist
		checklist = [
		  ("FPGA is programmed", self._fpga_programmed, None, None, True),
		]

		# Run this class's checklist
		self.do_checklist(checklist)

class R2dbe(Roach2):

	def __init__(self, host, bitcode=R2DBE_DEFAULT_BITCODE, parent_logger=module_logger, **kwargs):
		super(R2dbe, self).__init__(host, **kwargs)
		self.logger = logging.getLogger("{name}[host={host!r}]".format(name=".".join((parent_logger.name, 
		  self.__class__.__name__)), host=self.host,))
		self.bitcode = bitcode
		self._inputs = [IFSignal(parent_logger=self.logger), ] * R2DBE_NUM_INPUTS
		self._outputs = [EthRoute(parent_logger=self.logger), ] * R2DBE_NUM_OUTPUTS

	def __repr__(self):
		repr_str = "{name}"#[\n  {inputs[0]!r} : {outputs[0]!r}\n  {inputs[1]!r} : {outputs[1]!r}\n]"
		return repr_str.format(name=self.host, inputs=self._inputs, outputs=self._outputs)

	def _dump_8bit_counts_buffer(self, input_n):
		# Read buffer and interpret
		raw_bin = self.roach2.read(R2DBE_COUNTS_BUFFER % input_n, R2DBE_COUNTS_BUFFER_NMEM * R2DBE_COUNTS_BUFFER_SIZET)
		raw_int = array(unpack(R2DBE_COUNTS_BUFFER_FMT % R2DBE_COUNTS_BUFFER_NMEM, raw_bin), dtype=uint64)
		sec = (raw_int >> R2DBE_COUNTS_RSHIFT_SEC) & R2DBE_COUNTS_MASK_SEC
		cnt = (raw_int >> R2DBE_COUNTS_RSHIFT_CNT) & R2DBE_COUNTS_MASK_CNT

		# Reshape counts
		cnt = cnt.reshape(R2DBE_COUNTS_SHAPE).astype(uint32)

		# Reorder cores
		cnt = cnt[:,R2DBE_COUNTS_CORE_ORDER,:]

		# Roll to take care of 2's complement representation
		cnt = roll(cnt,R2DBE_COUNTS_ROLL_BY,axis=R2DBE_COUNTS_ROLL_AXIS)

		# Only keep unique time values
		sec = sec.reshape(R2DBE_COUNTS_SHAPE)[:, 0, 0].astype(uint32)

		# Apply time offset to absolute reference
		sec = self._offset_alive_sec(sec)

		# Create sample value array to return
		val = arange(-R2DBE_COUNTS_SHAPE[-1]/2, R2DBE_COUNTS_SHAPE[-1]/2, 1).astype(int)

		return sec, cnt, val

	def _dump_8bit_counts_mean_variance(self, input_n):
		# Get counts
		sec, cnt, val = self._dump_8bit_counts_buffer(input_n)

		# Reshape val for proper broadcasting
		val = val.reshape((1, 1, -1))

		# Get discrete probability distribution
		p = cnt.astype(float) / cnt.sum(axis=-1).reshape((R2DBE_COUNTS_SHAPE[0], R2DBE_COUNTS_SHAPE[1], 1))

		# Calculate mean and variance
		means = (p*val).sum(axis=-1)
		variances = (p*(val - means.reshape((R2DBE_COUNTS_SHAPE[0], R2DBE_COUNTS_SHAPE[1], 1)))**2).sum(axis=-1)

		return sec, means, variances

	def _dump_power_buffer(self, input_n):
		# Read buffer and interpret
		raw_bin = self.roach2.read(R2DBE_POWER_BUFFER % input_n, R2DBE_POWER_BUFFER_NMEM * R2DBE_POWER_BUFFER_SIZET)
		raw_int = array(unpack(R2DBE_POWER_BUFFER_FMT % R2DBE_POWER_BUFFER_NMEM, raw_bin), dtype=uint64)
		msc = (raw_int >> R2DBE_POWER_RSHIFT_MSC) & R2DBE_POWER_MASK_MSC
		sec = (raw_int >> R2DBE_POWER_RSHIFT_SEC) & R2DBE_POWER_MASK_SEC
		pwr = (raw_int >> R2DBE_POWER_RSHIFT_PWR) & R2DBE_POWER_MASK_PWR

		# Apply time offset to absolute reference
		sec = self._offset_alive_sec(sec)

		return msc, sec, pwr

	def _offset_alive_sec(self, sec):
		abs_time = self._read_int(R2DBE_ONEPPS_SINCE_EPOCH)
		alive = self._read_int(R2DBE_ONEPPS_ALIVE)
		offset = abs_time - alive

		return sec + offset

	def _unpack_2bit_data(self, data):
		# Interpret data as array of uint32
		N_bytes = len(data)
		N_uint32 = N_bytes / 4
		uint32_data = array(unpack(">%dI" % N_uint32, data), dtype=uint32)

		# Extract uint2 from uint32
		N_int2 = N_bytes * 4
		uint2_data = zeros(N_int2, dtype=int8)
		bits_per_sample = 2
		samples_per_word = 16
		sample_max = 2**bits_per_sample - 1
		for ii in range(samples_per_word):
			shift_by = 30 - bits_per_sample * ii
			uint2_data[ii::samples_per_word] = (uint32_data >> shift_by) & sample_max

		# Convert offset binary to signed
		int2_data = uint2_data - 2**(bits_per_sample - 1)

		return int2_data

	def _unpack_8bit_data(self, data):
		# Interpret data as array of int8
		N_bytes = len(data)
		int8_data = array(unpack(">%db" % N_bytes, data), dtype=int8)

		return int8_data

	@classmethod
	def make_default_route_from_destination(cls, dst_mac, dst_ip, dst_port=Port(4001)):
		dst = EthEntity(mac_addr_entity=dst_mac, ip_addr_entity=dst_ip, port_entity=dst_port)
		src_ip = IPAddress((dst_ip.address & 0xFFFFFF00) + 254)
		src_mac = MACAddress((2<<40) + (2<<32) + src_ip.address)
		src_port = Port(dst_port.port - 1)
		src = EthEntity(mac_addr_entity=src_mac, ip_addr_entity=src_ip, port_entity=src_port)
		return EthRoute(source_entity=src, destination_entity=dst)

	def adc_interface_cal(self, input_n):

		success = True

		# Set data input source to ADC (store current setting)
		data_select = self.get_input_data_source(input_n)
		self.set_input_data_source(input_n, R2DBE_INPUT_DATA_SOURCE_ADC)

		# Set ADC test mode
		adc5g.set_test_mode(self.roach2, input_n)
		adc5g.sync_adc(self.roach2)

		# Do calibration
		opt, glitches = adc5g.calibrate_mmcm_phase(self.roach2, input_n, [R2DBE_DATA_SNAPSHOT_8BIT % input_n,])
		gstr = adc5g.pretty_glitch_profile(opt, glitches)
		if opt is None:
			success = False
			self.logger.error("{ADC{0} interface calibration failed, no optimal phase found: {1} [{2}]".format(input_n, opt, gstr))
		else:
			self.logger.info("ADC{0} calibration found optimal phase: {1} [{2}]".format(input_n, opt, gstr))

		# Unset ADC test mode
		adc5g.unset_test_mode(self.roach2, input_n)

		# Restore input source
		self.set_input_data_source(input_n, data_select)

		return success

	def adc_core_cal(self, input_n, max_iter=5, curb_gain_step=0.5, curb_offset_step=0.5):

		success = True

		# Reset core gain parameters
		self.logger.debug("Resetting ADC{0} core gain parameters".format(input_n))
		adc.set_core_gains(self.roach2, input_n, [0]*4)

		# Get current gain settings
		gains_0 = adc.get_core_gains(self.roach2, input_n)

		# Wait for new settings to take effect
		sleep(3)

		# Get reset standard deviations
		sec, _, variances = self._dump_8bit_counts_mean_variance(input_n)
		std_0 = sqrt(variances[sec.argmax()-1, :])
		self.logger.debug("Initial ADC{0} standard deviations are [{1}]".format(input_n,
		  ", ".join(["{0:+.3f}".format(s) for s in std_0])))

		# Take reference standard deviation as mean across all cores
		std_ref = std_0.mean()
		self.logger.debug("Reference standard deviation for ADC{0} is {1:.3f}".format(input_n, std_ref))

		# Compute gain adjustment per core
		gain_adj = 100*(1.0 - std_0 / std_ref) * curb_gain_step

		# Store best gain parameters
		best_gains = gains_0
		best_gains_adj = abs(gain_adj)
		best_gains_std = std_0

		# Feed back initial gain adjustment
		curr_gains = adc.adj_core_gains(self.roach2, input_n, gain_adj)
		self.logger.debug("Initial gain adjustments for ADC{0} are [{1}] % (updated gains are [{2}] %)".format(input_n,
		  ", ".join(["{0:+.3f}".format(a) for a in gain_adj]), ", ".join(["{0:+.3f}".format(g) for g in curr_gains])))

		# Now iterate until gain solution converges
		tries = 0
		while True:
			# Wait for new settings to take effect
			sleep(3)

			# Measure new standard deviations
			sec, _, variances = self._dump_8bit_counts_mean_variance(input_n)
			std_u = sqrt(variances[sec.argmax()-1, :])
			self.logger.debug("Updated standard deviations for ADC{0} are [{1}]".format(input_n,
			  ", ".join(["{0:+.3f}".format(s) for s in std_u])))

			# Compute gain adjustment per core
			gain_adj = 100*(1.0 - std_u / std_ref) * curb_gain_step

			# Zero any gain adjustment smaller than the resolution
			gain_adj[abs(gain_adj) < adc.GAIN_PER_STEP * curb_gain_step] = 0

			# Keep settings that yield smallest absolute adjustment
			for ii in range(len(gain_adj)):
				if abs(gain_adj[ii]) < abs(best_gains_adj[ii]):
					best_gains[ii] = curr_gains[ii]
					best_gains_adj[ii] = gain_adj[ii]
					best_gains_std[ii] = std_u[ii]

			# If gain adjustments are zero, exit
			if (gain_adj == 0).all():
				self.logger.debug("ADC{0} core gain solution converged".format(input_n))
				break

			# Feed back update
			curr_gains = adc.adj_core_gains(self.roach2, input_n, gain_adj)

			self.logger.debug("Updated gain adjustments for ADC{0} are [{1}] % (updated gains are [{2}] %)".format(input_n,
			  ", ".join(["{0:+.3f}".format(a) for a in gain_adj]),
			  ", ".join(["{0:+.3f}".format(g) for g in curr_gains])))

			# Increment tries and abort if necessary
			tries += 1
			if tries >= max_iter:
				self.logger.warn("Maximum number of iterations for ADC{0} core gain cal reached, using best result".format(
				  input_n))
				adc.set_core_gains(self.roach2, input_n, best_gains)
				success = False
				break

		self.logger.debug("ADC{0} core gain solution: [{1}] (standard deviations were [{2}])".format(input_n,
		  ", ".join(["{0:+.3f}".format(g) for g in adc.get_core_gains(self.roach2, input_n)]),
		  ", ".join(["{0:+.3f}".format(s) for s in best_gains_std])))

		# Reset core offset parameters
		self.logger.debug("Resetting ADC{0} core offset parameters".format(input_n))
		adc.set_core_offsets(self.roach2, input_n, [0]*4)

		# Get current offset settings
		offsets_0 = adc.get_core_offsets(self.roach2, input_n)

		# Wait for new settings to take effect
		sleep(3)

		# Get reset mean
		sec, means, _ = self._dump_8bit_counts_mean_variance(input_n)
		mean_0 = means[sec.argmax()-1, :]
		self.logger.debug("Initial ADC{0} means are [{1}]".format(input_n,
		  ", ".join(["{0:+.3f}".format(m) for m in mean_0])))

		# Compute offset adjustment per core
		offset_adj = -mean_0 * curb_offset_step

		# Store best offset parameters
		best_offsets = offsets_0
		best_offsets_adj = abs(offset_adj)
		best_offsets_mean = mean_0

		# Feed back initial gain adjustment
		curr_offsets = adc.adj_core_offsets(self.roach2, input_n, offset_adj)
		self.logger.debug("Initial offset adjustments for ADC{0} are [{1}] (updated offsets are [{2}])".format(input_n,
		  ", ".join(["{0:+.3f}".format(a) for a in offset_adj]),
		  ", ".join(["{0:+.3f}".format(o) for o in curr_offsets])))

		# Now iterate until offset solution converges
		tries = 0
		while True:
			# Wait for new settings to take effect
			sleep(3)

			# Measure new means
			sec, means, _ = self._dump_8bit_counts_mean_variance(input_n)
			mean_u = means[sec.argmax()-1, :]
			self.logger.debug("Updated means for ADC{0} are [{1}]".format(input_n,
			  ", ".join(["{0:+.3f}".format(m) for m in mean_u])))

			# Compute offset adjustment per core
			offset_adj = -mean_u * curb_offset_step

			# Zero any offset adjustment smaller than the resolution
			offset_adj[abs(offset_adj) < adc.OFFSET_LSB_STEP * curb_offset_step] = 0

			# Keep settings that yield smallest absolute adjustment
			for ii in range(len(offset_adj)):
				if abs(offset_adj[ii]) < abs(best_offsets_adj[ii]):
					best_offsets[ii] = curr_offsets[ii]
					best_offsets_adj[ii] = offset_adj[ii]
					best_offsets_mean[ii] = mean_u[ii]

			# If offset adjustments are zero, exit
			if (offset_adj == 0).all():
				self.logger.debug("ADC{0} core offset solution converged".format(input_n))
				break

			# Feed back update
			curr_offsets = adc.adj_core_offsets(self.roach2, input_n, offset_adj)

			self.logger.debug("Updated offset adjustments for ADC{0} are [{1}] (updated offsets are [{2}])".format(input_n,
			  ", ".join(["{0:+.3f}".format(a) for a in offset_adj]),
			  ", ".join(["{0:+.3f}".format(o) for o in curr_offsets])))

			# Increment tries and abort if necessary
			tries += 1
			if tries >= max_iter:
				self.logger.warn("Maximum number of iterations for ADC{0} core offset cal reached, using best result".format(
				  input_n))
				adc.set_core_offsets(self.roach2, input_n, best_offsets)
				success = False
				break

		self.logger.debug("ADC{0} core offset solution: [{1}] (means were [{2}])".format(input_n,
		  ", ".join(["{0:+.3f}".format(o) for o in adc.get_core_offsets(self.roach2, input_n)]),
		  ", ".join(["{0:+.3f}".format(m) for m in best_offsets_mean])))

		return success

	def arm_one_pps(self):
		self._write_int(R2DBE_ONEPPS_CTRL, 1<<31)
		self._write_int(R2DBE_ONEPPS_CTRL, 0)

		# Wait until at least one full second has passed
		sleep(2)

	def enable_vdif_transmission(self, output_n):
		self._write_int(R2DBE_VDIF_ENABLE % output_n, 1)

	def get_2bit_and_8bit_snapshot(self, input_n):
		# If input specifier not a list, make it a 1-element list
		list_input = True
		if not isinstance(input_n, list):
			list_input = False
			input_n = list((input_n,))

		# Get snapshots
		snap_names = []
		snap_names_2bit = [R2DBE_DATA_SNAPSHOT_2BIT % ii for ii in input_n]
		snap_names.extend(snap_names_2bit)
		snap_names_8bit = [R2DBE_DATA_SNAPSHOT_8BIT % ii for ii in input_n]
		snap_names.extend(snap_names_8bit)
		snaps = self._read_snap(snap_names)

		# Get 2-bit samples
		data_2bit = [snaps["data"][snap_names.index(name_2bit)] for name_2bit in snap_names_2bit]
		samples_2bit = [self._unpack_2bit_data(data) for data in data_2bit]

		# Get 8-bit samples
		data_8bit = [snaps["data"][snap_names.index(name_8bit)] for name_8bit in snap_names_8bit]
		samples_8bit = [self._unpack_8bit_data(data) for data in data_8bit]

		# If input specifier not a list, revert to non-list result
		if not list_input:
			samples_2bit = samples_2bit[0]
			samples_8bit = samples_8bit[0]

		return samples_2bit, samples_8bit

	def get_2bit_snapshot(self, input_n):
		# If input specifier not a list, make it a 1-element list
		list_input = True
		if not isinstance(input_n, list):
			list_input = False
			input_n = list((input_n,))

		# Get snapshots
		snaps = self._read_snap([R2DBE_DATA_SNAPSHOT_2BIT % ii for ii in input_n])

		# Unpack into 2-bit samples
		samples = [self._unpack_2bit_data(data) for data in snaps['data']]

		# If input specifier not a list, revert to non-list result
		if not list_input:
			samples = samples[0]

		return samples

	def get_2bit_state_counts(self, input_n, reuse_samples=None):
		# If input specifier not a list, make it a 1-element list
		list_input = True
		if not isinstance(input_n, list):
			list_input = False
			input_n = list((input_n,))
			reuse_samples = [reuse_samples]

		# Optionally use provided sample data
		samples = reuse_samples
		if any([s is None for s in samples]):
			samples = self.get_2bit_snapshot(input_n)

		# Count the number of samples in each state
		all_states = range(-2, 2)
		state_counts = list(zeros((len(input_n), len(all_states)), dtype=uint32))
		for ii, inp in enumerate(input_n):
			for jj, state in enumerate(all_states):
				state_counts[ii][jj] = count_nonzero(samples[ii] == state)

		# Make a list of state values
		state_values = [array(all_states, dtype=int8) for _ in state_counts]

		# If input specifier not a list, revert to non-list result
		if not list_input:
			state_counts = state_counts[0]
			state_values = state_values[0]

		return state_counts, state_values

	def get_2bit_threshold(self, input_n):
		# If input specifier not a list, make it a 1-element list
		list_input = True
		if not isinstance(input_n, list):
			list_input = False
			input_n = list((input_n,))

		th = [self._read_int(R2DBE_QUANTIZATION_THRESHOLD % inp_n) & 0x7F for inp_n in input_n]

		# If input specifier not a list, revert to non-list result
		if not list_input:
			th = th[0]

		return th

	def get_8bit_snapshot(self, input_n):
		# If input specifier not a list, make it a 1-element list
		list_input = True
		if not isinstance(input_n, list):
			list_input = False
			input_n = list((input_n,))

		# Get snapshots
		snaps = self._read_snap([R2DBE_DATA_SNAPSHOT_8BIT % ii for ii in input_n])

		# Unpack into 8-bit samples
		samples = [self._unpack_8bit_data(data) for data in snaps['data']]

		# If input specifier not a list, revert to non-list result
		if not list_input:
			samples = samples[0]

		return samples

	def get_8bit_state_counts(self, input_n):
		# If input specifier not a list, make it a 1-element list
		list_input = True
		if not isinstance(input_n, list):
			list_input = False
			input_n = list((input_n,))

		# Count the number of samples in each state
		state_counts = []
		state_values = []
		for inp in input_n:
			sec, cnt, val = self._dump_8bit_counts_buffer(inp)
			# Select only second-to-last entry, and sum over all ADC cores
			state_counts.append(cnt[sec.argmax()-1, :, :].sum(axis=0))
			state_values.append(val)

		# If input specifier not a list, revert to non-list result
		if not list_input:
			state_counts = state_counts[0]
			state_values = state_values[0]

		return state_counts, state_values

	def get_gps_pps_count(self):
		return self._read_int(R2DBE_ONEPPS_GPS_PPS_COUNT)

	def get_input(self, input_n):
		# If input specifier not a list, make it a 1-element list
		list_input = True
		if not isinstance(input_n, list):
			list_input = False
			input_n = list((input_n,))

		inp = []
		for inp_n in input_n:
			w4 = self._read_int(R2DBE_VDIF_HDR_W4 % inp_n)
			rx_sb_spec = (w4 & 0x04) >> 2
			bdc_sb_spec = (w4 & 0x02) >> 1
			pol_spec = w4 & 0x01
			inp.append(IFSignal(rx_sb_spec, bdc_sb_spec, pol_spec))

		# If input specifier not a list, revert to non-list result
		if not list_input:
			inp = inp[0]

		return inp

	def get_input_data_source(self, input_n):
		return self._read_int(R2DBE_INPUT_DATA_SELECT % input_n)

	def get_output(self, output_n):
		# If output specifier not a list, make it a 1-element list
		list_output = True
		if not isinstance(output_n, list):
			list_output = False
			output_n = list((output_n,))

		outp = []
		for outp_n in output_n:
			# Read 10GbE core details
			tengbe_details = self.roach2.get_10gbe_core_details(R2DBE_TENGBE_CORE % outp_n)

			# Get source parameters
			src_ip = tengbe_details["my_ip"]
			src_port = tengbe_details["fabric_port"]
			src_mac = tengbe_details["mymac"]

			# Get destination parameters
			dst_ip = self.roach2.read_uint(R2DBE_TENGBE_DEST_IP % outp_n)
			dst_port = self.roach2.read_uint(R2DBE_TENGBE_DEST_PORT % outp_n)
			dst_mac = tengbe_details["arp"][dst_ip & 0xFF]

			# Build EthRoute
			src = EthEntity(mac_addr_entity=MACAddress(src_mac),
			  ip_addr_entity=IPAddress(src_ip),
			  port_entity=Port(src_port))
			dst = EthEntity(mac_addr_entity=MACAddress(dst_mac),
			  ip_addr_entity=IPAddress(dst_ip),
			  port_entity=Port(dst_port))
			outp.append(EthRoute(source_entity=src, destination_entity=dst))

		# If output specifier not a list, revert to non-list result
		if not list_output:
			outp = outp[0]

		return outp

	def get_gps_pps_clock_offset(self):
		return self._read_int(R2DBE_ONEPPS_GPS_OFFSET)

	def get_gps_pps_time_offset(self):
		return self.get_gps_pps_clock_offset() / R2DBE_CLOCK_RATE

	def get_station_id(self, output_n):
		# If output specifier not a list, make it a 1-element list
		list_output = True
		if not isinstance(output_n, list):
			list_output = False
			output_n = list((output_n,))

		st = []
		for outp_n in output_n:
			st.append("".join([chr((self._read_int(R2DBE_VDIF_STATION_ID % outp_n) >> ss) & 0xFF) for ss in [8, 0]]))

		# If output specifier not a list, revert to non-list result
		if not list_output:
			st = st[0]

		return st

	def get_time(self, output_n=0):
		sec = self._read_int(R2DBE_ONEPPS_SINCE_EPOCH)
		ep = self._read_int(R2DBE_VDIF_REF_EPOCH % output_n)

		return VDIFTime(ep, sec).to_datetime()

	def get_up_time(self):
		alive = self._read_int(R2DBE_ONEPPS_ALIVE)

		return alive

	def set_2bit_threshold(self, input_n, threshold=None, outer_bin_frac=0.16, wait=0):
		# If threshold is not specified, compute it
		if threshold is None:
			# Wait given number of seconds, in case of recent power level change
			sleep(wait)

			# Read counts
			sec, cnt, val = self._dump_8bit_counts_buffer(input_n)

			# Use only data from second-to-last entry, and sum over cores
			cnt_1sec = cnt[sec.argmax()-1,:,:].sum(axis=0)

			# Compute cumulative distribution function
			cdf_1sec = cnt_1sec.cumsum(axis=0).astype(float)/cnt_1sec.sum()
			
			# Compute thresholds for positive and negative sides, then average
			th_pos = val[nonzero(cdf_1sec < 1.0-outer_bin_frac)[0][-1]]
			th_neg = val[nonzero(cdf_1sec > outer_bin_frac)[0][0]]
			threshold = int(round((abs(th_pos) + abs(th_neg))/2.0))

		self._write_int(R2DBE_QUANTIZATION_THRESHOLD % input_n, threshold)
		self.logger.debug("Set 2-bit quantization threshold for input {0} to {1} (pos {2:+}, neg {3:+})".format(
		  input_n, threshold, th_pos, th_neg))

	def set_input(self, input_n, ifsig_inst):
		self.logger.info("(Analog) if{0} input is {1!r}".format(input_n, ifsig_inst))

		w4 = (R2DBE_VDIF_EUD_VERSION<<24) + (ifsig_inst["RxSB"]<<2) + (ifsig_inst["BDCSB"]<<1) + ifsig_inst["Pol"]
		self._write_int(R2DBE_VDIF_HDR_W4 % input_n, w4)

	def set_input_data_source(self, input_n, source):
		self._write_int(R2DBE_INPUT_DATA_SELECT % input_n, source)

	def set_output(self, output_n, ethrt_inst, thread_id=None):
		self.logger.info("(10GbE) SLOT0 CH{0} route is {1!r}".format(output_n, ethrt_inst))

		# Get source & destination addresses
		src_ip = ethrt_inst.src["IP"]
		src_port = ethrt_inst.src["Port"]
		src_mac = ethrt_inst.src["MAC"]
		dst_ip = ethrt_inst.dst["IP"]
		dst_port = ethrt_inst.dst["Port"]
		dst_mac = ethrt_inst.dst["MAC"]

		# Populate ARP table
		arp = [0xFFFFFFFF] * 256
		arp[dst_ip & 0x0FF] = dst_mac

		# Configure core and write destination parameters
		self.roach2.config_10gbe_core(R2DBE_TENGBE_CORE % output_n, 
		  src_mac, src_ip, src_port, arp)
		self._write_int(R2DBE_TENGBE_DEST_IP % output_n, dst_ip)
		self._write_int(R2DBE_TENGBE_DEST_PORT % output_n, dst_port)
		
		# Reset transmission
		self._write_int(R2DBE_TENGBE_RESET % output_n, 1)
		self._write_int(R2DBE_TENGBE_RESET % output_n, 0)

	def set_real_time(self):
		# reset VDIF time keeping
		for output_n in R2DBE_OUTPUTS:
			self._write_int(R2DBE_VDIF_RESET % output_n, 1)

		# Wait until the middle of a second to set absolute time
		while (abs(datetime.utcnow().microsecond - 5e5) > 1e5):
			sleep(0.1)

		# Calculate current time VDIF specification (discard frame)
		vdif_time = VDIFTime.from_datetime(datetime.utcnow(), frame_rate=R2DBE_FRAME_RATE, suppress_microsecond=True)

		# enable VDIF time keeping
		for output_n in R2DBE_OUTPUTS:
			self._write_int(R2DBE_VDIF_RESET % output_n, 0)
		
		# write time reference registers
		for output_n in R2DBE_OUTPUTS:
			self._write_int(R2DBE_VDIF_SEC_SINCE_REF_EPOCH % output_n, vdif_time.sec)
			self._write_int(R2DBE_VDIF_REF_EPOCH % output_n, vdif_time.epoch)

		self.logger.info("Time reference is {0!r}".format(vdif_time))

	def set_station_id(self, output_n, station_id):
		station_id_formatted = (ord(station_id[0])<<8) + ord(station_id[1])
		self._write_int(R2DBE_VDIF_STATION_ID % output_n, station_id_formatted)

	def set_thread_id(self, output_n, thread_id=None):
		# Use default if none given
		if thread_id is None:
			thread_id = R2DBE_VDIF_DEFAULT_THREAD_IDS[output_n]

		self._write_int(R2DBE_VDIF_THREAD_ID % output_n, thread_id)

	def get_vdif_data_mode(self, output_n):
		reorder_2bit = self._read_uint(R2DBE_VDIF_REORDER_2BIT % output_n) & 0x01 == 1
		little_endian = self._read_uint(R2DBE_VDIF_LITTLE_ENDIAN % output_n) & 0x01 == 1
		data_not_test = not (self._read_uint(R2DBE_VDIF_TEST_SELECT % output_n) & 0x01 == 1)

		return reorder_2bit, little_endian, data_not_test

	def set_vdif_data_mode(self, output_n, reorder_2bit=True, little_endian=True, data_not_test=True):
		self._write_int(R2DBE_VDIF_REORDER_2BIT % output_n, int(reorder_2bit))
		self._write_int(R2DBE_VDIF_LITTLE_ENDIAN % output_n, int(little_endian))
		self._write_int(R2DBE_VDIF_TEST_SELECT % output_n, int(not data_not_test))

	def config_object(self, cfg):
		self._station = cfg.station
		self._inputs = cfg.inputs
		self._outputs = cfg.outputs

	def config_device(self, cfg):

		# Program bitcode
		bitcode_version = self._program(self.bitcode)
		self.logger.info("Programmed bitcode '{0}' ({1})".format(self.bitcode, bitcode_version))
		if bitcode_version.find(R2DBE_LATEST_VERSION_GIT_HASH) == -1:
			self.logger.warn("Bitcode does not correspond to latest version which has hash {0}".format(
			  R2DBE_LATEST_VERSION_GIT_HASH))
		elif bitcode_version.find("dirty") != -1:
			self.logger.warn("Bitcode is dirty")

		# Do ADC interface calibration
		self.logger.info("Performing ADC interface calibration")
		for ii in R2DBE_INPUTS:
			self.do_check("ADC{0} interface calibration".format(ii),
			  partial(self.adc_interface_cal,ii), None, None, False)

		# Set inputs
		self.logger.info("Defining analog inputs")
		for ii, inp in enumerate(cfg.inputs):
			self.set_input_data_source(ii, R2DBE_INPUT_DATA_SOURCE_ADC)
			self.set_input(ii, inp)

		# Arm 1PPS
		self.logger.info("Synchronizing to 1PPS")
		self.arm_one_pps()

		# Set absolute time reference
		self.logger.info("Setting absolute time reference")
		self.set_real_time()

		# Set outputs / VDIF parameters
		self.logger.info("Defining ethernet outputs")
		for ii, outp in enumerate(cfg.outputs):
			self.set_output(ii, outp)
			self.set_station_id(ii, cfg.station)
			self.set_thread_id(ii, R2DBE_VDIF_DEFAULT_THREAD_IDS[ii])

			# Set the data source / format
			self.set_vdif_data_mode(ii)

		# Give PPS signal time to propagate
		sleep(2)

		# Enable VDIF cores
		self.logger.info("Enabling VDIF transmission")
		for ii, _ in enumerate(cfg.outputs):
			self._write_int(R2DBE_VDIF_ENABLE % ii, 1)

		# Do ADC core calibration
		self.logger.info("Performing ADC core calibration")
		for ii, _ in enumerate(cfg.inputs):
			self.do_check("ADC{0} core calibration".format(ii),
			  partial(self.adc_core_cal,ii), None, None, False)

		# Set 2-bit thresholds
		self.logger.info("Setting 2-bit quantization thresholds")
		for ii, _ in enumerate(cfg.inputs):
			self.set_2bit_threshold(ii)

	@property
	def device_config(self):
		try:
			rc = R2dbeConfig(self.get_station_id(0), self.get_input(0), self.get_input(1),
			  self.get_output(0), self.get_output(1))
			return rc
		except:
			return None

	@property
	def device_is_configured(self):
		"""Check if the device is configured.

		For an R2dbe device this is True if all of the following conditions are
		met:
		  1. The FPGA is programmed with the correct bitcode
		  2. Input data source is set to ADC for both inputs
		  3. Output VDIF data mode for both outputs is set to:
		    3.1 reorder_2bit
		    3.2 little_endian
		    3.3 data_not_test
		  4. VDIF transmission is enabled
		"""

		# FPGA should be running the correct bitcode
		if not self._running_correct_bitcode():
			return False

		# for each input, ...
		for ii in R2DBE_INPUTS:
			# ... ADC should be the input data source
			if not self.get_input_data_source(ii) == R2DBE_INPUT_DATA_SOURCE_ADC:
				return False

		# for each output, ...
		for ii in R2DBE_OUTPUTS:

			# ... VDIF data mode should give (True, True, True)
			for rt in self.get_vdif_data_mode(ii):
				if not rt:
					return False

			# ... VDIF transmission should be enabled
			if not self.vdif_transmission_enabled(ii):
				return False

		return True

	@property
	def object_config(self):
		try:
			rc = R2dbeConfig(self._station, self._inputs[0], self._inputs[1],
			  self._outputs[0], self._outputs[1])
			return rc
		except:
			return None

	def setup(self, station, inputs, outputs):

		# Create an R2dbeConfig from the given parameters
		rc = R2dbeConfig(station, inputs[0], inputs[1], outputs[0], outputs[1])

		# Set the object configuration
		self.config_object(rc)

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
		self.config_device(rc)

	def vdif_transmission_enabled(self, output_n):
		return (self._read_uint(R2DBE_VDIF_ENABLE % output_n) & 0x01) == 1

	def _running_correct_bitcode(self):
		"""Check if the FPGA is programmed with the correct bitcode."""
		# If FPGA not programmed, short-circuit to False
		if not self._fpga_programmed():
			return False

		# If not correct version (different hash OR matching hash but dirty), False
		bitcode_version = format_bitcode_version(self.roach2.get_rcs())
		if bitcode_version.find(R2DBE_LATEST_VERSION_GIT_HASH) == -1 or \
		  bitcode_version.find("dirty") != -1:
			return False

		# If we reach this point, programmed with right bitcode
		return True

	def pre_config_checks(self):

		# Do super's pre-config checks first
		super(Roach2, self).pre_config_checks()

		# Compile the checklist
		checklist = []

		# Run this class's checklist
		self.do_checklist(checklist)

	def post_config_checks(self):

		# Do super's pre-config checks first
		super(Roach2, self).post_config_checks()

		# Compile the checklist
		checklist = [
		  ("programmed with correct bitcode", self._running_correct_bitcode, None, None, True),
		]

		# Run this class's checklist
		self.do_checklist(checklist)
