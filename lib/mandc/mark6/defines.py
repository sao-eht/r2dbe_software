# Miscellaneous
MARK6_DEFAULT_USER = "oper"

MARK6_INPUTS = (0, 1)
MARK6_OUTPUTS = (0, 1, 2, 3)
MARK6_MODULES = [1, 2, 3, 4]

MOD_TYPE_SG = "sg"
MOD_DISKNO = 8

# Input stream defintions by data source type
R2DBE_SOURCE_TYPE = "r2dbe"
R2DBE_DATA_FORMAT = "vdif"
R2DBE_PAYLOAD_SIZE = 8224
R2DBE_PAYLOAD_OFFSET = 50
R2DBE_PSN_OFFSET = 42

SOURCE_TYPES = [R2DBE_SOURCE_TYPE]

# VSI return code meanings
VSI_SUCCESS = 0
VSI_BUSY = 1
VSI_NOT_IMPLEMENTED = 2
VSI_SYNTAX_ERROR = 3
VSI_RUNTIME_ERROR = 4
VSI_TOO_BUSY = 5
VSI_INCONSISTENT = 6
VSI_UNKNOWN_KEYWORD = 7
VSI_PARAMETER_ERROR = 8
VSI_INDETERMINATE_STATE = 9

CPLANE_SUCCESS = 0

# Expected values for checks
LSSCSI_DISKS = 32
NTPQ_MAX_OFFSET = 0.100
VV_MAX_OFFSET = 0.01
GROUP_REF = "1234"
