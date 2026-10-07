import csv
import os
import random
from typing import Dict

from data_quality_platform.contracts import SOURCE_COLUMNS, STATE_ZIP_PREFIXES


FIRST_NAMES_VALID = [
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael",
    "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan",
    "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen",
    "Charles", "Lisa", "Daniel", "Nancy", "Matthew", "Betty", "Anthony",
    "Margaret", "Mark", "Sandra", "Donald", "Ashley", "Steven", "Kimberly",
    "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle", "Kenneth",
    "Carol", "Kevin", "Amanda", "Brian", "Dorothy", "George", "Melissa",
    "Timothy", "Deborah",
]

LAST_NAMES_VALID = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez",
    "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin",
    "Lee", "Perez", "Thompson", "White", "Harris", "Sanchez", "Clark",
    "Ramirez", "Lewis", "Robinson", "Walker", "Young", "Allen", "King",
    "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores", "Green",
    "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts",
]

SUSPICIOUS_FIRST_NAMES = ["test", "fake", "xxx", "admin", "null", "asdf", "aaa", "bbb"]
SUSPICIOUS_LAST_NAMES = ["dummy", "zzz", "test", "fake", "xyz", "qwerty"]

CITIES = [
    "New York", "Los Angeles", "Chicago", "Houston", "Phoenix",
    "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose",
    "Austin", "Jacksonville", "Fort Worth", "Columbus", "Charlotte",
    "San Francisco", "Indianapolis", "Seattle", "Denver", "Washington",
]

STATES = list(STATE_ZIP_PREFIXES.keys())

DOMAINS = ["example.com", "test.org", "mail.com", "web.net", "company.co", "business.io"]

INTERESTS_MAIN = ["technology", "sports", "fashion", "finance", "health", "travel", "food", "music"]
INTERESTS_SUB = ["mobile", "football", "casual", "investing", "fitness", "domestic", "organic", "rock"]


class SyntheticDataGenerator:
    """Deterministic synthetic data generator for 33-column consumer dataset.

    Generates controlled quality defects for testing.
    Deterministic for the same seed.
    """

    def __init__(self, seed: int = 20260821):
        self.rng = random.Random(seed)
        self.seed = seed

    def _state_zip(self) -> tuple:
        """Generate a consistent state+zip pair."""
        state = self.rng.choice(STATES)
        prefixes = STATE_ZIP_PREFIXES[state]
        prefix = self.rng.choice(prefixes)
        zip_suffix = self.rng.randint(100, 9999)
        zip_code = f"{prefix}{zip_suffix:04d}"[:5]
        return state, zip_code

    def _state_zip_mismatch(self) -> tuple:
        """Generate a deliberate ZIP/state mismatch."""
        state = self.rng.choice(STATES)
        # Pick a different state's ZIP prefix
        other_states = [s for s in STATES if s != state]
        other_state = self.rng.choice(other_states)
        prefixes = STATE_ZIP_PREFIXES[other_state]
        prefix = self.rng.choice(prefixes)
        zip_suffix = self.rng.randint(100, 9999)
        zip_code = f"{prefix}{zip_suffix:04d}"[:5]
        return state, zip_code

    def _generate_row(self, row_id: int, defect_mode: str = "valid") -> Dict[str, str]:
        """Generate a single row with a specific defect mode."""
        rng = self.rng

        if defect_mode == "blank_email":
            state, zip_code = self._state_zip()
            first = rng.choice(FIRST_NAMES_VALID)
            last = rng.choice(LAST_NAMES_VALID)
            email = ""
        elif defect_mode == "malformed_email":
            state, zip_code = self._state_zip()
            first = rng.choice(FIRST_NAMES_VALID)
            last = rng.choice(LAST_NAMES_VALID)
            malformed = ["not-an-email", "@missing-local.com", "no-at-sign", "spaces in@email.com", "double@@at.com"]
            email = rng.choice(malformed)
        elif defect_mode == "suspicious_first_name":
            state, zip_code = self._state_zip()
            first = rng.choice(SUSPICIOUS_FIRST_NAMES)
            last = rng.choice(LAST_NAMES_VALID)
            email = f"{first.lower()}.{last.lower()}@{rng.choice(DOMAINS)}"
        elif defect_mode == "suspicious_last_name":
            state, zip_code = self._state_zip()
            first = rng.choice(FIRST_NAMES_VALID)
            last = rng.choice(SUSPICIOUS_LAST_NAMES)
            email = f"{first.lower()}.{last.lower()}@{rng.choice(DOMAINS)}"
        elif defect_mode == "zip_state_mismatch":
            state, zip_code = self._state_zip_mismatch()
            first = rng.choice(FIRST_NAMES_VALID)
            last = rng.choice(LAST_NAMES_VALID)
            email = f"{first.lower()}.{last.lower()}@{rng.choice(DOMAINS)}"
        elif defect_mode == "same_name":
            state, zip_code = self._state_zip()
            first = rng.choice(FIRST_NAMES_VALID)
            last = first  # Same first and last name
            email = f"{first.lower()}.{last.lower()}@{rng.choice(DOMAINS)}"
        elif defect_mode == "missing_values":
            state, zip_code = self._state_zip()
            first = ""
            last = rng.choice(LAST_NAMES_VALID)
            email = f"{last.lower()}@{rng.choice(DOMAINS)}"
        elif defect_mode == "blank_all_names":
            state, zip_code = self._state_zip()
            first = ""
            last = ""
            email = f"user{row_id}@{rng.choice(DOMAINS)}"
        else:
            # Valid row
            state, zip_code = self._state_zip()
            first = rng.choice(FIRST_NAMES_VALID)
            last = rng.choice(LAST_NAMES_VALID)
            email = f"{first.lower()}.{last.lower()}{row_id}@{rng.choice(DOMAINS)}"

        city = rng.choice(CITIES)
        domain = rng.choice(DOMAINS)
        phone = f"{rng.randint(200,999)}-{rng.randint(100,999)}-{rng.randint(1000,9999)}"
        gender = rng.choice(["M", "F", "Other"])
        dob = f"{rng.randint(1950,2005):04d}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"
        reg_date = f"{rng.randint(2020,2026):04d}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}"
        valid_flag = "1" if defect_mode == "valid" else rng.choice(["0", "1"])
        ethnicity = rng.choice(["White", "Hispanic", "Black", "Asian", "Other", ""])
        ownrent = rng.choice(["Own", "Rent", ""])
        main_interest = rng.choice(INTERESTS_MAIN)
        sub_interest = rng.choice(INTERESTS_SUB)
        lat = f"{rng.uniform(25.0, 48.0):.6f}"
        lon = f"{rng.uniform(-125.0, -70.0):.6f}"
        uploaded = reg_date
        country = "US"
        websource_id = str(rng.randint(1, 100))
        interest_ids = f"{rng.randint(1,50)},{rng.randint(51,100)}"
        dnc = rng.choice(["0", "1", ""])
        source = rng.choice(["web", "api", "import", "manual"])
        first_norm = first.lower().strip() if first else ""
        last_norm = last.lower().strip() if last else ""
        zip_norm = zip_code

        return {
            "id": str(row_id),
            "email_address": email,
            "first_name": first,
            "last_name": last,
            "address": f"{rng.randint(100,9999)} Main St",
            "city": city,
            "county_name": f"{city} County",
            "state": state,
            "zip": zip_code,
            "website_source": domain,
            "phone_number": phone,
            "gender": gender,
            "dob": dob,
            "registration_date": reg_date,
            "valid": valid_flag,
            "extra": "",
            "email_id": f"email_{row_id}",
            "ethnicity": ethnicity,
            "ownrent": ownrent,
            "domain": domain,
            "main_interest": main_interest,
            "sub_interest": sub_interest,
            "latitude": lat,
            "longitude": lon,
            "uploaded": uploaded,
            "country": country,
            "websource_id": websource_id,
            "interest_ids": interest_ids,
            "DNC": dnc,
            "source": source,
            "first_name_norm": first_norm,
            "last_name_norm": last_norm,
            "zip_norm": zip_norm,
        }

    def generate(self, num_rows: int, output_path: str) -> str:
        """Generate a synthetic CSV dataset.

        Uses deterministic defect injection with controlled proportions:
        - ~65% valid rows
        - ~8% blank emails
        - ~7% malformed emails
        - ~5% suspicious first names
        - ~5% suspicious last names
        - ~5% ZIP/state mismatches
        - ~3% same-name rows
        - ~2% missing values
        """
        defect_modes = ["valid"] * 65 + ["blank_email"] * 8 + ["malformed_email"] * 7 + \
                      ["suspicious_first_name"] * 5 + ["suspicious_last_name"] * 5 + \
                      ["zip_state_mismatch"] * 5 + ["same_name"] * 3 + ["missing_values"] * 2

        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=SOURCE_COLUMNS)
            writer.writeheader()
            for i in range(1, num_rows + 1):
                mode = defect_modes[i % len(defect_modes)]
                row = self._generate_row(i, mode)
                writer.writerow(row)

        return output_path
