# Connection parameters
DEFAULT_PORT = 23
TIMEOUT_AFTER = 5
WAIT_RESPONSE = 0.05

# Command set
OPERATOR_SET = ""
OPERATOR_QUERY = "?"
SEP = " "

QUERY_BY_NUMBER = "n"
QUERY_BY_TEXT = "t"

CMD_IDENTIFY = "*idn"

CMD_BAND = "band"
BAND_5TO9 = "5-9"#,"0","hi"
BAND_5TO9_NUMBER = 0
BAND_4TO8 = "4-8"#,"1","lo"
BAND_4TO8_NUMBER = 1

CMD_ATTENUATOR = "attn"
POL_ZERO = "P0"
POL_ONE = "P1"
SUBBAND_LOWER = "L"
SUBBAND_UPPER = "U"
ATTENUATOR_MAP = {
  BAND_4TO8: {
    POL_ZERO: {
      SUBBAND_LOWER: "0",
      SUBBAND_UPPER: "2"},
    POL_ONE: {
      SUBBAND_LOWER: "4",
      SUBBAND_UPPER: "6"}},
  BAND_5TO9: {
    POL_ZERO: {
      SUBBAND_LOWER: "1",
      SUBBAND_UPPER: "3"},
    POL_ONE: {
      SUBBAND_LOWER: "5",
      SUBBAND_UPPER: "7"}}}

ATTENUATOR_MIN = 0.0
ATTENUATOR_MAX = 31.5

CMD_LOCK = "lock"
LOCK_FAULT = "FAULT"
LOCK_OFF = "OFF"
LOCK_UNLOCKED = "UNLOCKED"
LOCK_LOCKED = "LOCKED"
LOCK_STATUS = {
  "-2": LOCK_FAULT,
  "-1": LOCK_OFF,
  "0": LOCK_UNLOCKED,
  "1": LOCK_LOCKED}

CMD_STATUS = "stat"

CMD_CTRL = "ctrl"
CTRL_NONE = "none"
CTRL_LOCAL = "local"
CTRL_REMOTE = "remote"
CTRL_BOTH = "both"
CTRL_CLEAR = "clear"

CMD_FREQUENCY = "freq"

CMD_SYNTH_MAP = "smap"

CMD_CONF = "conf"

CMD_EMULATION = "emul"

# Set responses
OKAY = "OK"
ERROR = "ERR"
