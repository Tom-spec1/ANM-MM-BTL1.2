"""Project-wide identity required by BTL 1.2."""

STUDENT_IDS = ("2252211", "2213078", "2433220", "2410482")
STUDENT_ID_JOINED = "-".join(STUDENT_IDS)
ROOT_CA_COMMON_NAME = f"CA-Root-{STUDENT_ID_JOINED}"
ROOT_CA_ORGANIZATIONAL_UNIT = (
    "Faculty of Computer Science and Engineer - " + STUDENT_ID_JOINED
)
ROOT_CA_ORGANIZATION = "PKI Project"
ROOT_CA_COUNTRY = "VN"
ROOT_CA_STATE = "Ho Chi Minh"
ROOT_CA_LOCALITY = "Ho Chi Minh City"

# Demo-only passphrase used to make the submitted lab state reproducible.
# Runtime code also accepts PKI_ROOT_CA_PASSPHRASE from the environment.
DEMO_ROOT_CA_PASSPHRASE = "BTL1-PKI-DEMO-LOCAL"
