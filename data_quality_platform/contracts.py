"""Data contracts: schema definitions, flag columns, and validation constants."""

# ── Source schema: exactly 33 columns in this order ──
SOURCE_COLUMNS = [
    "id", "email_address", "first_name", "last_name", "address",
    "city", "county_name", "state", "zip", "website_source",
    "phone_number", "gender", "dob", "registration_date", "valid",
    "extra", "email_id", "ethnicity", "ownrent", "domain",
    "main_interest", "sub_interest", "latitude", "longitude", "uploaded",
    "country", "websource_id", "interest_ids", "DNC", "source",
    "first_name_norm", "last_name_norm", "zip_norm",
]

EXPECTED_COLUMN_COUNT = 33

# ── 8 quality flag columns ──
FLAG_COLUMNS = [
    "first_name_cleaning_candidate",
    "last_name_cleaning_candidate",
    "name_cleaning_candidate",
    "email_blank",
    "email_syntax_failure",
    "proposed_email_export_eligible",
    "zip_state_assessable",
    "geography_mismatch_candidate",
]

EXPECTED_FLAG_COUNT = 8
TOTAL_OUTPUT_COLUMNS = EXPECTED_COLUMN_COUNT + EXPECTED_FLAG_COUNT  # 41

# ── Output column order: source columns first, then flags ──
OUTPUT_COLUMNS = SOURCE_COLUMNS + FLAG_COLUMNS

# ── Rule IDs (canonical, versioned) ──
REQUIRED_RULE_IDS = [
    "first_name_cleaning_candidate",
    "last_name_cleaning_candidate",
    "name_cleaning_candidate",
    "email_blank",
    "email_syntax_failure",
    "proposed_email_export_eligible",
    "zip_state_assessable",
    "geography_mismatch_candidate",
]

# ── US state → valid ZIP prefix mapping (first 1-3 digits) ──
STATE_ZIP_PREFIXES = {
    "AL": ["35", "36"], "AK": ["99"], "AZ": ["85", "86"],
    "AR": ["71", "72"], "CA": ["90", "91", "92", "93", "94", "95", "96"],
    "CO": ["80", "81"], "CT": ["06"], "DE": ["19"],
    "DC": ["20", "20"], "FL": ["32", "33", "34"], "GA": ["30", "31"],
    "HI": ["96", "97"], "ID": ["83", "84"], "IL": ["60", "61", "62"],
    "IN": ["46", "47"], "IA": ["50", "51", "52"], "KS": ["66", "67"],
    "KY": ["40", "41", "42"], "LA": ["70", "71"], "ME": ["03", "04"],
    "MD": ["21", "22"], "MA": ["01", "02"], "MI": ["48", "49"],
    "MN": ["55", "56"], "MS": ["38", "39"], "MO": ["63", "64", "65"],
    "MT": ["59"], "NE": ["68", "69"], "NV": ["88", "89"],
    "NH": ["03"], "NJ": ["07", "08"], "NM": ["87", "88"],
    "NY": ["10", "11", "12", "13", "14"], "NC": ["27", "28"],
    "ND": ["58"], "OH": ["43", "44", "45"], "OK": ["73", "74"],
    "OR": ["97"], "PA": ["15", "16", "17", "18", "19"],
    "RI": ["02", "03"], "SC": ["29"], "SD": ["57"],
    "TN": ["37", "38"], "TX": ["75", "76", "77", "78", "79"],
    "UT": ["84"], "VT": ["05"], "VA": ["22", "23", "24"],
    "WA": ["98", "99"], "WV": ["24", "25", "26"],
    "WI": ["53", "54"], "WY": ["82", "83"],
}

# ── Suspicious name patterns (for cleaning candidate detection) ──
SUSPICIOUS_NAME_PATTERNS = [
    "test", "fake", "dummy", "xxx", "zzz", "aaa", "bbb",
    "admin", "null", "none", "na", "n/a", "unknown",
    "example", "sample", "asdf", "qwerty", "abc", "xyz",
]

# ── Validation statuses ──
VERIFIED = "VERIFIED"
PARTIALLY_VERIFIED = "PARTIALLY_VERIFIED"
DESIGNED_BUT_NOT_RUNTIME_VERIFIED = "DESIGNED_BUT_NOT_RUNTIME_VERIFIED"
NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
LATER = "LATER"
