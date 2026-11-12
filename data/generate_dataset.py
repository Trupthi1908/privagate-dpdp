"""Synthetic Indian Enterprise Document Generator for DPDP Evaluation.

Generates 50 realistic Indian enterprise documents across 4 categories with exact ground truth:
1. Loan Applications
2. KYC Documents
3. Customer Support Tickets (including Hinglish code-mixing)
4. Insurance Claims

All ID strings (Aadhaar, PAN, GSTIN, Voter ID, Passport) are dynamically synthesized at runtime.
No static 12-digit numbers are hardcoded.
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path
from typing import Any, Dict, List, Tuple

DATA_DIR = Path(__file__).resolve().parent
OUTPUT_FILE = DATA_DIR / "synthetic_50.json"

FIRST_NAMES = [
    "Rahul", "Priya", "Amit", "Sneha", "Vikram", "Ananya", "Rohan", "Pooja",
    "Suresh", "Kavita", "Deepak", "Sunita", "Arjun", "Meera", "Manoj", "Divya",
    "Siddharth", "Neha", "Rajesh", "Aarti", "Gaurav", "Swati", "Naveen", "Shilpa",
    "Pradeep", "Rashmi", "Alok", "Nandini", "Harish", "Preeti", "Kiran", "Tanvi"
]

LAST_NAMES = [
    "Sharma", "Verma", "Gupta", "Patel", "Iyer", "Nair", "Reddy", "Rao",
    "Deshmukh", "Kulkarni", "Mehta", "Singh", "Joshi", "Bhat", "Hegde", "Chatterjee",
    "Mukherjee", "Das", "Agarwal", "Chopra", "Malhotra", "Kapoor", "Gowda", "Shetty"
]

CITIES_LOCALITIES = [
    ("Bengaluru", "Indiranagar", "560038"),
    ("Bengaluru", "Koramangala", "560034"),
    ("Bengaluru", "JP Nagar", "560078"),
    ("Davangere", "Vidyanagar", "577004"),
    ("Davangere", "MCC B Block", "577002"),
    ("Mumbai", "Andheri West", "400058"),
    ("Mumbai", "Bandra Kurla Complex", "400051"),
    ("New Delhi", "Connaught Place", "110001"),
    ("New Delhi", "Dwarka Sector 10", "110075"),
    ("Hyderabad", "Madhapur", "500081"),
    ("Hyderabad", "Banjara Hills", "500034"),
    ("Pune", "Kothrud", "411038"),
    ("Pune", "Viman Nagar", "411014"),
    ("Chennai", "T Nagar", "600017"),
    ("Noida", "Sector 62", "201309"),
    ("Gurugram", "DLF Phase 2", "122002"),
]


def gen_aadhaar(rng: random.Random) -> str:
    """Generates a dynamic 12-digit Aadhaar number with space formatting at runtime."""
    part1 = "".join(str(rng.randint(2, 9)) if i == 0 else str(rng.randint(0, 9)) for i in range(4))
    part2 = "".join(str(rng.randint(0, 9)) for _ in range(4))
    part3 = "".join(str(rng.randint(0, 9)) for _ in range(4))
    return f"{part1} {part2} {part3}"


def gen_pan(rng: random.Random) -> str:
    """Generates a dynamic 10-char PAN string: 5 uppercase letters, 4 digits, 1 uppercase letter."""
    letters1 = "".join(rng.choice(string.ascii_uppercase) for _ in range(5))
    digits = "".join(str(rng.randint(0, 9)) for _ in range(4))
    letter2 = rng.choice(string.ascii_uppercase)
    return f"{letters1}{digits}{letter2}"


def gen_gstin(rng: random.Random, pan: str) -> str:
    """Generates a dynamic 15-char GSTIN string: 2 state digits + 10-char PAN + 1 digit + 'Z' + 1 checksum digit."""
    state_code = f"{rng.randint(1, 35):02d}"
    entity_code = str(rng.randint(1, 9))
    check = rng.choice(string.ascii_uppercase + string.digits)
    return f"{state_code}{pan}{entity_code}Z{check}"


def gen_voter_id(rng: random.Random) -> str:
    """Generates a dynamic Voter ID (EPIC): 3 uppercase letters followed by 7 digits."""
    prefix = "".join(rng.choice(string.ascii_uppercase) for _ in range(3))
    digits = "".join(str(rng.randint(0, 9)) for _ in range(7))
    return f"{prefix}{digits}"


def gen_passport(rng: random.Random) -> str:
    """Generates a dynamic Indian Passport: 1 uppercase letter + 7 digits (first and last digits non-zero)."""
    valid_letters = [c for c in string.ascii_uppercase if c not in ("Q", "X", "Z")]
    p_letter = rng.choice(valid_letters)
    d1 = str(rng.randint(1, 9))
    mid = "".join(str(rng.randint(0, 9)) for _ in range(5))
    d7 = str(rng.randint(1, 9))
    return f"{p_letter}{d1}{mid}{d7}"


def gen_person(rng: random.Random) -> str:
    return f"{rng.choice(FIRST_NAMES)} {rng.choice(LAST_NAMES)}"


def gen_address(rng: random.Random) -> str:
    flat_no = rng.randint(101, 908)
    city, locality, pincode = rng.choice(CITIES_LOCALITIES)
    cross = f"{rng.randint(1, 15)}th Cross"
    main = f"{rng.randint(1, 8)}th Main Road"
    return f"Flat No {flat_no}, {cross}, {main}, {locality}, {city} - {pincode}"


def build_doc(template: str, substitutions: Dict[str, Tuple[str, str]]) -> Tuple[str, List[Dict[str, Any]]]:
    """Builds a document from template and records ground-truth entity spans precisely.

    substitutions: {placeholder_key: (entity_type, entity_value)}
    """
    text = template
    entities: List[Dict[str, Any]] = []

    # Replace keys in order
    for key, (entity_type, val) in substitutions.items():
        placeholder = f"{{{key}}}"
        idx = text.find(placeholder)
        while idx != -1:
            text = text[:idx] + val + text[idx + len(placeholder):]
            entities.append({
                "entity_type": entity_type,
                "text": val,
                "start": idx,
                "end": idx + len(val),
            })
            idx = text.find(placeholder, idx + len(val))

    # Sort entities by start offset
    entities.sort(key=lambda x: x["start"])
    return text, entities


def generate_50_documents() -> List[Dict[str, Any]]:
    rng = random.Random(42)
    documents = []
    doc_id = 1

    # 1. 15 Loan Applications
    loan_templates = [
        (
            "RETAIL ASSET FINANCE - PERSONAL LOAN APPLICATION\n"
            "Application Ref: LOAN-IN-{ref_num}\n"
            "Applicant Name: {person_name}\n"
            "Residential Address: {address}\n"
            "Identity Verification:\n"
            "- Aadhaar Number: {aadhaar}\n"
            "- Permanent Account Number (PAN): {pan}\n"
            "- Passport Number: {passport}\n"
            "Loan Request: Rs. {amount} for home renovation tenure 36 months.\n"
            "Employer: Tata Consultancy Services, Bengaluru.\n"
            "Declaration: I, {person_name}, hereby confirm that all submitted DPDP consent data is accurate."
        ),
        (
            "COMMERCIAL BUSINESS CREDIT EVALUATION MEMORANDUM\n"
            "Applicant Entity: Apex Technologies Private Limited\n"
            "Key Managing Director: {person_name}\n"
            "Corporate PAN: {pan}\n"
            "Registered GSTIN: {gstin}\n"
            "Director Aadhaar: {aadhaar}\n"
            "Registered Office: {address}\n"
            "Sanction Amount: INR {amount} working capital credit facility.\n"
            "Primary Contact: {person_name} (authorized signatory)."
        ),
        (
            "SECURED HOUSING LOAN SANCTION NOTE\n"
            "Primary Borrower: {person_name}\n"
            "Current Address: {address}\n"
            "KYC Identifiers:\n"
            "1. Aadhaar Card: {aadhaar}\n"
            "2. Income Tax PAN: {pan}\n"
            "3. Voter ID Card: {voter_id}\n"
            "Property Valuation: INR 85,00,000 at Whitefield.\n"
            "Disbursement requested by {person_name} following title deed verification."
        ),
    ]

    for i in range(15):
        tpl = loan_templates[i % len(loan_templates)]
        person = gen_person(rng)
        pan = gen_pan(rng)
        subs = {
            "ref_num": ("METADATA", str(rng.randint(100000, 999999))),
            "person_name": ("PERSON", person),
            "address": ("ADDRESS", gen_address(rng)),
            "aadhaar": ("AADHAAR", gen_aadhaar(rng)),
            "pan": ("PAN", pan),
            "gstin": ("GSTIN", gen_gstin(rng, pan)),
            "passport": ("PASSPORT", gen_passport(rng)),
            "voter_id": ("VOTER_ID", gen_voter_id(rng)),
            "amount": ("METADATA", f"{rng.randint(3, 45)},00,000"),
        }
        text, ents = build_doc(tpl, subs)
        documents.append({
            "id": f"DOC_{doc_id:03d}",
            "category": "loan_application",
            "title": f"Loan Application - {person}",
            "text": text,
            "entities": [e for e in ents if e["entity_type"] != "METADATA"],
        })
        doc_id += 1

    # 2. 15 KYC Documents
    kyc_templates = [
        (
            "VERIFIED DIGITAL KYC RECORD - CENTRAL REGISTRY (CKYC)\n"
            "Customer Full Name: {person_name}\n"
            "Father's Name: S/O {father_name}\n"
            "Permanent Address: {address}\n"
            "Official Valid Documents (OVDs):\n"
            "- UIDAI Aadhaar: {aadhaar}\n"
            "- Income Tax Department PAN: {pan}\n"
            "- Election Commission Voter ID: {voter_id}\n"
            "- Republic of India Passport: {passport}\n"
            "Verification Officer: Branch Manager, SBI Bengaluru.\n"
            "CKYC Status: Authenticated for {person_name} under DPDP Rules 2025."
        ),
        (
            "ANNUAL CUSTOMER DUE DILIGENCE (CDD) PROFILE\n"
            "Client Identity: {person_name}\n"
            "Current Address: {address}\n"
            "Tax Identification: PAN {pan} with Aadhaar linking {aadhaar}.\n"
            "Secondary OVD: Passport {passport}.\n"
            "Risk Category: Low Risk Individual Account.\n"
            "All notifications to be dispatched to {person_name}."
        ),
        (
            "MSME ENTERPRISE ONBOARDING & BENEFICIAL OWNER KYC\n"
            "Entity Trade Name: Sri Manjunatha Logistics\n"
            "Sole Proprietor: {person_name}\n"
            "Operating Address: {address}\n"
            "Enterprise GSTIN: {gstin}\n"
            "Proprietor PAN: {pan}\n"
            "Proprietor Aadhaar: {aadhaar}\n"
            "Voter ID: {voter_id}\n"
            "Consent for CIBIL & GST fetch approved by {person_name}."
        ),
    ]

    for i in range(15):
        tpl = kyc_templates[i % len(kyc_templates)]
        person = gen_person(rng)
        father = gen_person(rng)
        pan = gen_pan(rng)
        subs = {
            "person_name": ("PERSON", person),
            "father_name": ("PERSON", father),
            "address": ("ADDRESS", gen_address(rng)),
            "aadhaar": ("AADHAAR", gen_aadhaar(rng)),
            "pan": ("PAN", pan),
            "gstin": ("GSTIN", gen_gstin(rng, pan)),
            "voter_id": ("VOTER_ID", gen_voter_id(rng)),
            "passport": ("PASSPORT", gen_passport(rng)),
        }
        text, ents = build_doc(tpl, subs)
        documents.append({
            "id": f"DOC_{doc_id:03d}",
            "category": "kyc_document",
            "title": f"KYC Record - {person}",
            "text": text,
            "entities": [e for e in ents if e["entity_type"] != "METADATA"],
        })
        doc_id += 1

    # 3. 10 Customer Support Tickets (Indian English & Hinglish code-mixing)
    ticket_templates = [
        (
            "SUPPORT TICKET #TCK-{tck_num}: URGENT KYC RE-VERIFICATION\n"
            "Customer Name: {person_name}\n"
            "Message:\n"
            "Hello Support Team,\n"
            "Mera naam {person_name} hai aur mera savings account temporarily freeze ho gaya hai. "
            "Branch walon ne kaha ki re-KYC pending hai. Maine apna Aadhaar card {aadhaar} "
            "aur PAN card {pan} upload kiya tha portal par. "
            "Mera current residential address hai: {address}. "
            "Aap please verify karke mera account activate kar dijiye. Regards, {person_name}."
        ),
        (
            "SUPPORT TICKET #TCK-{tck_num}: FASTAG RECHARGE AND REFUND GRIEVANCE\n"
            "Applicant Name: {person_name}\n"
            "Message:\n"
            "Sir, mera payment FASTag wallet me deduct ho gaya par wallet update nahi hua. "
            "Verification ke liye mera Voter ID {voter_id} aur PAN {pan} attached hai. "
            "Mera registered address {address} hai. Please check and credit back. "
            "Thanks, {person_name}."
        ),
        (
            "SUPPORT TICKET #TCK-{tck_num}: GST INVOICE RECONCILIATION DISCREPANCY\n"
            "Client Name: {person_name}\n"
            "Message:\n"
            "Greetings Helpdesk, hamare B2B billing me GST credit reflect nahi ho raha hai. "
            "Our company GSTIN is {gstin} registered against PAN {pan}. "
            "Authorized contact person is {person_name}, resident of {address}. "
            "Kindly resolve the input tax discrepancy urgently."
        ),
        (
            "SUPPORT TICKET #TCK-{tck_num}: INTERNATIONAL ROAMING & SIM RE-ISSUE\n"
            "Subscriber Name: {person_name}\n"
            "Message:\n"
            "Namaste Team, mera SIM card international travel ke dauran damage ho gaya. "
            "Mera passport number hai {passport} aur Aadhaar number hai {aadhaar}. "
            "Please send the replacement eSIM or physical SIM to my residence: {address}. "
            "Mera naam {person_name} hai. Thank you."
        ),
    ]

    for i in range(10):
        tpl = ticket_templates[i % len(ticket_templates)]
        person = gen_person(rng)
        pan = gen_pan(rng)
        subs = {
            "tck_num": ("METADATA", str(rng.randint(10000, 99999))),
            "person_name": ("PERSON", person),
            "address": ("ADDRESS", gen_address(rng)),
            "aadhaar": ("AADHAAR", gen_aadhaar(rng)),
            "pan": ("PAN", pan),
            "gstin": ("GSTIN", gen_gstin(rng, pan)),
            "voter_id": ("VOTER_ID", gen_voter_id(rng)),
            "passport": ("PASSPORT", gen_passport(rng)),
        }
        text, ents = build_doc(tpl, subs)
        documents.append({
            "id": f"DOC_{doc_id:03d}",
            "category": "customer_support",
            "title": f"Support Ticket - {person}",
            "text": text,
            "entities": [e for e in ents if e["entity_type"] != "METADATA"],
        })
        doc_id += 1

    # 4. 10 Insurance Claims
    insurance_templates = [
        (
            "HEALTH INSURANCE CASHLESS HOSPITALIZATION CLAIM FORM\n"
            "Claim Number: CLM-HEALTH-{clm_num}\n"
            "Insured Patient Name: {person_name}\n"
            "Nominee Name: S/O {nominee_name}\n"
            "Policyholder Address: {address}\n"
            "Identity Proofs:\n"
            "- Patient Aadhaar: {aadhaar}\n"
            "- Taxpayer PAN: {pan}\n"
            "- Passport ID: {passport}\n"
            "Diagnosis: Acute appendicitis, Manipal Hospital Bengaluru.\n"
            "Approved Settlement: Rs. 1,45,000.\n"
            "Claimant signature authorized by {person_name}."
        ),
        (
            "MOTOR VEHICLE THIRD-PARTY ACCIDENT SETTLEMENT CLAIM\n"
            "Claim Reference: MOT-IN-{clm_num}\n"
            "Registered Owner: {person_name}\n"
            "Owner Address: {address}\n"
            "Owner PAN: {pan}\n"
            "Owner Aadhaar: {aadhaar}\n"
            "Owner Voter Card: {voter_id}\n"
            "Vehicle Registration: KA-04-MB-4521.\n"
            "Surveyor assessment approved for payment directly to {person_name}."
        ),
    ]

    for i in range(10):
        tpl = insurance_templates[i % len(insurance_templates)]
        person = gen_person(rng)
        nominee = gen_person(rng)
        pan = gen_pan(rng)
        subs = {
            "clm_num": ("METADATA", str(rng.randint(100000, 999999))),
            "person_name": ("PERSON", person),
            "nominee_name": ("PERSON", nominee),
            "address": ("ADDRESS", gen_address(rng)),
            "aadhaar": ("AADHAAR", gen_aadhaar(rng)),
            "pan": ("PAN", pan),
            "voter_id": ("VOTER_ID", gen_voter_id(rng)),
            "passport": ("PASSPORT", gen_passport(rng)),
        }
        text, ents = build_doc(tpl, subs)
        documents.append({
            "id": f"DOC_{doc_id:03d}",
            "category": "insurance_claim",
            "title": f"Insurance Claim - {person}",
            "text": text,
            "entities": [e for e in ents if e["entity_type"] != "METADATA"],
        })
        doc_id += 1

    return documents


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    docs = generate_50_documents()
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(docs, f, indent=2, ensure_ascii=False)
    print(f"Successfully generated {len(docs)} synthetic Indian enterprise documents into {OUTPUT_FILE}")


if __name__ == "__main__":
    main()

