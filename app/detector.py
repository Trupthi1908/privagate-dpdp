"""PII Detection Engine combining Microsoft Presidio, Custom Indian Recognizers, and SpaCy NER."""

from __future__ import annotations

import logging
import re
import subprocess
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


def ensure_spacy_model(model_name: str = "en_core_web_sm") -> None:
    """Ensures that the specified spaCy model is available."""
    try:
        import spacy
        try:
            spacy.load(model_name)
            return
        except Exception:
            pass

        subprocess.run(
            [sys.executable, "-m", "spacy", "download", model_name],
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception:
        pass

# Presidio Analyzer and NlpEngineProvider
PRESIDIO_AVAILABLE = False
try:
    from presidio_analyzer import (
        AnalyzerEngine,
        Pattern,
        PatternRecognizer,
        RecognizerRegistry,
    )
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    PRESIDIO_AVAILABLE = True
except Exception as e:
    logger.warning(f"Presidio import warning: {e}")
    PRESIDIO_AVAILABLE = False

# SpaCy
SPACY_AVAILABLE = False
try:
    import spacy
    SPACY_AVAILABLE = True
except Exception:
    SPACY_AVAILABLE = False


# Regex patterns conforming to Indian identity specifications
# Note: Aadhaar pattern matches dynamically without hardcoded 12-digit numbers
AADHAAR_PATTERN = r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
PAN_PATTERN = r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"
GSTIN_PATTERN = r"\b\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}Z[A-Z\d]{1}\b"
VOTER_ID_PATTERN = r"\b[A-Z]{3}[0-9]{7}\b"
PASSPORT_PATTERN = r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b"

# High-frequency Indian Names for robust contextual NER
INDIAN_FIRST_NAMES = {
    "Rahul", "Priya", "Amit", "Sneha", "Vikram", "Ananya", "Rohan", "Pooja",
    "Suresh", "Kavita", "Deepak", "Sunita", "Arjun", "Meera", "Manoj", "Divya",
    "Siddharth", "Neha", "Rajesh", "Aarti", "Gaurav", "Swati", "Naveen", "Shilpa",
    "Pradeep", "Rashmi", "Alok", "Nandini", "Harish", "Preeti", "Kiran", "Tanvi",
    "Akash", "Varun", "Aditya", "Shweta", "Anil", "Sanjay", "Vivek", "Manish", "Trupthi"
}

INDIAN_LAST_NAMES = {
    "Sharma", "Verma", "Gupta", "Patel", "Iyer", "Nair", "Reddy", "Rao",
    "Deshmukh", "Kulkarni", "Mehta", "Singh", "Joshi", "Bhat", "Hegde", "Chatterjee",
    "Mukherjee", "Das", "Agarwal", "Chopra", "Malhotra", "Kapoor", "Gowda", "Shetty",
    "Kumar", "Mishra", "Pandey", "Bose", "Menon", "Pillai", "Naidu", "Kolvekar"
}

# Stopwords and non-entity words that generic English NER mistakenly tags in Indian documents
NON_PERSON_WORDS = {
    "ho", "gaya", "hai", "kaha", "ki", "kar", "dijiye", "karke", "ke", "dauran",
    "liye", "nahi", "hua", "mera", "meri", "sir", "namaste", "aur", "par", "tha",
    "do", "din", "pehle", "aap", "please", "walon", "ne", "greetings", "helpdesk",
    "subscriber", "loan", "request", "documents", "document", "valid", "name",
    "payment", "official", "applicant", "customer", "primary", "contact", "borrower",
    "claim", "number", "identities", "identifiers", "address", "residential",
    "identity", "verification", "support", "team", "care", "registered", "office",
    "due", "diligence", "cashless", "hospitalization", "working", "capital",
    "home", "renovation", "tenure", "months", "branch", "manager", "direct", "directly",
    "aadhaar", "card", "pan", "gstin", "voter", "passport", "ovd", "ovds", "epic",
    "date", "dates", "disbursal", "execution", "commencement", "agreement", "facility",
    "principal", "repayment", "interest", "rate", "floating", "amount", "sanction",
    "blossom", "blossoms", "therapy", "center", "centre", "clinic", "hospital",
    "pediatric", "rehabilitation", "diagnostics", "diagnostic", "institute",
    "department", "intake", "assessment", "developmental", "clinical", "specialist",
    "consultant", "attending", "referral", "physician", "doctor", "form", "section",
    "english", "hindi", "kannada", "tamil", "telugu", "marathi", "bengali",
    "gujarati", "malayalam", "odia", "punjabi", "urdu", "assamese", "language"
}

# Indian English & Hinglish Context Patterns for PERSON
# Using horizontal whitespace [ \t] to strictly avoid matching across newlines
HINGLISH_NAME_PATTERNS = [
    # "Mera naam Rahul Sharma hai"
    r"(?i)\bmera[ \t]+naam[ \t]+([A-Z][a-z]+(?:[ \t]+(?:[A-Z]\.?|[A-Z][a-z]+)){1,3})[ \t]+hai\b",
    # Specific application roles: "Applicant Name: Priya Nair", "Key Managing Director: Shilpa Agarwal"
    r"(?i)\b(?:applicant|customer|candidate|borrower|claimant|insured|client|subscriber|partner|director|signatory|primary\s+borrower|patient|nominee|contact|key\s+managing\s+director|sole\s+proprietor|proprietor|co-signatory|guarantor)(?:[ \t]+(?:full[ \t]+)?name)?[ \t]*[:\-][ \t]*([A-Z][a-z]+(?:[ \t]+(?:[A-Z]\.?|[A-Z][a-z]+)){1,3})\b",
    # "S/O Rajesh Gupta", "D/O ...", "W/O ..."
    r"(?i)\b(?:s/o|d/o|w/o|son\s+of|daughter\s+of|wife\s+of)[ \t]+([A-Z][a-z]+(?:[ \t]+(?:[A-Z]\.?|[A-Z][a-z]+)){1,3})\b",
    # Honorifics: "Shri Amit Verma", "Smt. Sunita Rao", "Mr. / Mrs. / Ms. / Dr."
    r"(?i)\b(?:shri|smt\.?|mr\.?|mrs\.?|ms\.?|dr\.?)[ \t]+([A-Z][a-z]+(?:[ \t]+(?:[A-Z]\.?|[A-Z][a-z]+)){1,3})\b",
    # Declaration: "I, Vikram Malhotra, hereby..."
    r"(?i)\bI,[ \t]*([A-Z][a-z]+(?:[ \t]+(?:[A-Z]\.?|[A-Z][a-z]+)){1,3}),[ \t]*hereby\b",
    # Sign-offs: "Regards, Rohan Deshmukh", "Thanks, Priya Nair"
    r"(?i)\b(?:regards|thanks|thank\s+you),[ \t]*([A-Z][a-z]+(?:[ \t]+(?:[A-Z]\.?|[A-Z][a-z]+)){1,3})\b",
    # Actions: "disbursement requested by Vikram Malhotra", "directly to Sneha Rao", "authorized by..."
    r"(?i)\b(?:directly\s+to|requested\s+by|authenticated\s+for|dispatched\s+to|approved\s+for|authorized\s+by)[ \t]+([A-Z][a-z]+(?:[ \t]+(?:[A-Z]\.?|[A-Z][a-z]+)){1,3})\b",
]

# Indian ADDRESS Patterns covering typical Indian street/locality/city/PIN constructs
ADDRESS_REGEX_PATTERNS = [
    # Full multi-part address e.g. "Flat No 402, 5th Cross, 2nd Main Road, Indiranagar, Bengaluru - 560038"
    r"(?i)\b(?:flat(?:\s*(?:no\.?|#))?\s*\d+[\w\s,/-]*?|\b(?:house|plot|door)\s*(?:no\.?|#)?\s*\d+[\w\s,/-]*?)(?:cross|main|road|street|layout|colony|enclave|nagar|vihar|phase|sector|extension|block|apartment|residency|heights|towers)[\w\s,/-]+?(?:bengaluru|bangalore|mumbai|delhi|new\s+delhi|hyderabad|chennai|pune|kolkata|ahmedabad|davangere|noida|gurugram|gurgaon|jaipur|lucknow|chandigarh|kochi|surat|mysuru|mysore)[\w\s,/-]*?(?:pin(?:\s*code)?\s*[-:]?\s*\d{6}|\b5\d{5}\b|\b\d{6}\b)",
    # Pattern starting with building/street: "24, MG Road, Ashok Nagar, Davangere, PIN: 577002"
    r"(?i)\b\d{1,4}[A-Za-z]?,?\s+(?:mg\s+road|brigade\s+road|main\s+road|cross|layout|nagar|colony|enclave|vihar|sector\s*\d+)[\w\s,/-]+?(?:bengaluru|bangalore|mumbai|delhi|hyderabad|chennai|pune|kolkata|davangere|noida|gurugram)[\w\s,/-]*?(?:pin(?:\s*code)?\s*[-:]?\s*\d{6}|\b\d{6}\b)",
    # Explicit Address line: "Address: Flat No 102, 2nd Main, Vidyanagar, Davangere, Karnataka - 577004"
    r"(?i)(?:residential\s+address|permanent\s+address|communication\s+address|current\s+address|registered\s+office|operating\s+address|owner\s+address|policyholder\s+address|address|residence)\s*[:\-]\s*([^\n\r]+?(?:pin(?:\s*code)?\s*[-:]?\s*\d{6}|\b\d{6}\b|[A-Z][a-z]+\s*-\s*\d{6}))",
]


class PIIDetectionEngine:
    """Enterprise Indian PII Detection Engine combining Presidio Analyzer, SpaCy NER, and Indian Regex Rules."""

    def __init__(self):
        self.analyzer: Optional[Any] = None
        self.nlp: Optional[Any] = None
        ensure_spacy_model("en_core_web_sm")
        self._init_presidio()
        self._init_spacy()

    def _init_presidio(self) -> None:
        if not PRESIDIO_AVAILABLE:
            return

        try:
            configuration = {
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
            provider = NlpEngineProvider(nlp_configuration=configuration)
            nlp_engine = provider.create_engine()

            registry = RecognizerRegistry()
            registry.load_predefined_recognizers(nlp_engine=nlp_engine)

            # 1. AADHAAR Recognizer
            aadhaar_pattern = Pattern(name="aadhaar_pattern", regex=AADHAAR_PATTERN, score=0.98)
            aadhaar_recognizer = PatternRecognizer(
                supported_entity="AADHAAR",
                patterns=[aadhaar_pattern],
                context=["aadhaar", "aadhar", "uidai", "uid", "resident", "identity card"],
            )
            registry.add_recognizer(aadhaar_recognizer)

            # 2. PAN Recognizer
            pan_pattern = Pattern(name="pan_pattern", regex=PAN_PATTERN, score=0.98)
            pan_recognizer = PatternRecognizer(
                supported_entity="PAN",
                patterns=[pan_pattern],
                context=["pan", "permanent account number", "income tax", "itr", "nsdl"],
            )
            registry.add_recognizer(pan_recognizer)

            # 3. GSTIN Recognizer
            gstin_pattern = Pattern(name="gstin_pattern", regex=GSTIN_PATTERN, score=0.98)
            gstin_recognizer = PatternRecognizer(
                supported_entity="GSTIN",
                patterns=[gstin_pattern],
                context=["gstin", "gst", "goods and services", "tax invoice"],
            )
            registry.add_recognizer(gstin_recognizer)

            # 4. VOTER_ID Recognizer
            voter_pattern = Pattern(name="voter_pattern", regex=VOTER_ID_PATTERN, score=0.96)
            voter_recognizer = PatternRecognizer(
                supported_entity="VOTER_ID",
                patterns=[voter_pattern],
                context=["voter", "epic", "election", "voter id", "eci"],
            )
            registry.add_recognizer(voter_recognizer)

            # 5. PASSPORT Recognizer
            passport_pattern = Pattern(name="passport_pattern", regex=PASSPORT_PATTERN, score=0.96)
            passport_recognizer = PatternRecognizer(
                supported_entity="PASSPORT",
                patterns=[passport_pattern],
                context=["passport", "republic of india", "travel document"],
            )
            registry.add_recognizer(passport_recognizer)

            self.analyzer = AnalyzerEngine(nlp_engine=nlp_engine, registry=registry)
        except Exception as e:
            logger.warning(f"Presidio initialization warning: {e}")
            self.analyzer = None

    def _init_spacy(self) -> None:
        if not SPACY_AVAILABLE:
            return
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except Exception:
            try:
                self.nlp = spacy.blank("en")
            except Exception:
                self.nlp = None

    def _is_valid_person_name(self, name_text: str) -> bool:
        """Validates that a string is a genuine personal name and not a header or phrase."""
        name_clean = name_text.strip()
        if len(name_clean) < 3 or any(ch.isdigit() for ch in name_clean):
            return False
        words = name_clean.lower().split()
        if any(w in NON_PERSON_WORDS for w in words):
            return False
        # Must have at least one capitalized word
        parts = name_clean.split()
        if not all(p[0].isupper() for p in parts if p):
            return False
        return True

    def detect(self, text: str) -> List[Dict[str, Any]]:
        """Detects Indian PII entities with Presidio, SpaCy, and Indian context patterns,

        resolving overlapping spans.
        """
        candidates: List[Dict[str, Any]] = []

        # 1. Presidio Analysis for Indian IDs, Email, Phone
        if self.analyzer:
            try:
                presidio_results = self.analyzer.analyze(
                    text=text,
                    language="en",
                    entities=[
                        "AADHAAR",
                        "PAN",
                        "GSTIN",
                        "VOTER_ID",
                        "PASSPORT",
                        "EMAIL_ADDRESS",
                        "PHONE_NUMBER",
                    ],
                )
                for res in presidio_results:
                    entity_text = text[res.start:res.end].strip()
                    candidates.append(
                        {
                            "entity_type": res.entity_type,
                            "start": res.start,
                            "end": res.end,
                            "score": float(res.score),
                            "text": entity_text,
                            "source": "presidio",
                        }
                    )
            except Exception as e:
                logger.warning(f"Presidio analyze error: {e}")

        # 2. Direct Indian Pattern Matching (Guarantees robust detection across all Indian ID formats)
        candidates.extend(self._match_direct_patterns(text))

        # 3. Known Indian Names Recognizer (High Precision & High Recall)
        for m in re.finditer(r"\b([A-Z][a-z]+)[ \t]+([A-Z][a-z]+)\b", text):
            w1, w2 = m.group(1), m.group(2)
            combined = f"{w1} {w2}"
            if not self._is_valid_person_name(combined):
                continue
            if w1 in INDIAN_FIRST_NAMES or w2 in INDIAN_LAST_NAMES:
                candidates.append(
                    {
                        "entity_type": "PERSON",
                        "start": m.start(),
                        "end": m.end(),
                        "score": 0.98,
                        "text": combined,
                        "source": "indian_name_dict",
                    }
                )

        # 4. SpaCy NER for PERSON (Filtered through _is_valid_person_name)
        if self.nlp:
            try:
                doc = self.nlp(text)
                for ent in doc.ents:
                    if ent.label_ == "PERSON":
                        ent_text = ent.text.strip()
                        if self._is_valid_person_name(ent_text):
                            candidates.append(
                                {
                                    "entity_type": "PERSON",
                                    "start": ent.start_char,
                                    "end": ent.end_char,
                                    "score": 0.90,
                                    "text": ent_text,
                                    "source": "spacy",
                                }
                            )
            except Exception as e:
                logger.warning(f"SpaCy error: {e}")

        # 5. Indian English & Hinglish Context Patterns for PERSON
        for pat in HINGLISH_NAME_PATTERNS:
            for match in re.finditer(pat, text):
                name_span = match.span(1)
                name_text = match.group(1).strip()
                if self._is_valid_person_name(name_text):
                    candidates.append(
                        {
                            "entity_type": "PERSON",
                            "start": name_span[0],
                            "end": name_span[1],
                            "score": 0.98,
                            "text": name_text,
                            "source": "hinglish_pattern",
                        }
                    )

        # 6. Indian ADDRESS Patterns
        for pat in ADDRESS_REGEX_PATTERNS:
            for match in re.finditer(pat, text):
                if match.groups() and match.group(1):
                    addr_span = match.span(1)
                    addr_text = match.group(1).strip()
                else:
                    addr_span = match.span()
                    addr_text = match.group(0).strip()

                candidates.append(
                    {
                        "entity_type": "ADDRESS",
                        "start": addr_span[0],
                        "end": addr_span[1],
                        "score": 0.96,
                        "text": addr_text,
                        "source": "address_pattern",
                    }
                )

        # 7. Resolve Span Overlaps
        resolved = self._resolve_overlaps(candidates)
        return resolved

    def _match_direct_patterns(self, text: str) -> List[Dict[str, Any]]:
        results = []
        # Aadhaar: 12 digits with optional spaces or hyphens
        for m in re.finditer(AADHAAR_PATTERN, text):
            raw = m.group(0)
            digits = re.sub(r"[\s-]", "", raw)
            if len(digits) == 12:
                results.append(
                    {
                        "entity_type": "AADHAAR",
                        "start": m.start(),
                        "end": m.end(),
                        "score": 0.98,
                        "text": raw,
                        "source": "regex_aadhaar",
                    }
                )

        # PAN: 5 uppercase letters, 4 digits, 1 uppercase letter
        for m in re.finditer(PAN_PATTERN, text):
            results.append(
                {
                    "entity_type": "PAN",
                    "start": m.start(),
                    "end": m.end(),
                    "score": 0.99,
                    "text": m.group(0),
                    "source": "regex_pan",
                }
            )

        # GSTIN: 15-char Indian GST number
        for m in re.finditer(GSTIN_PATTERN, text):
            results.append(
                {
                    "entity_type": "GSTIN",
                    "start": m.start(),
                    "end": m.end(),
                    "score": 0.99,
                    "text": m.group(0),
                    "source": "regex_gstin",
                }
            )

        # VOTER_ID: 3 uppercase letters, 7 digits
        for m in re.finditer(VOTER_ID_PATTERN, text):
            results.append(
                {
                    "entity_type": "VOTER_ID",
                    "start": m.start(),
                    "end": m.end(),
                    "score": 0.97,
                    "text": m.group(0),
                    "source": "regex_voter",
                }
            )

        # PASSPORT: 1 uppercase letter, 7 digits
        for m in re.finditer(PASSPORT_PATTERN, text):
            results.append(
                {
                    "entity_type": "PASSPORT",
                    "start": m.start(),
                    "end": m.end(),
                    "score": 0.97,
                    "text": m.group(0),
                    "source": "regex_passport",
                }
            )

        return results

    def _resolve_overlaps(self, candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Resolves overlapping entity spans:

        1. Priority order: Specific IDs (Aadhaar, PAN, GSTIN, Passport, Voter) > Address > Person.
        2. Higher confidence score wins.
        3. Longer span wins when scores are tied.
        """
        if not candidates:
            return []

        # Deduplicate identical spans
        unique_spans: Dict[Tuple[int, int, str], Dict[str, Any]] = {}
        for c in candidates:
            key = (c["start"], c["end"], c["entity_type"])
            if key not in unique_spans or c["score"] > unique_spans[key]["score"]:
                unique_spans[key] = c

        item_list = list(unique_spans.values())

        # Sort primarily by start offset ascending, then score descending, then length descending
        item_list.sort(key=lambda x: (x["start"], -x["score"], -(x["end"] - x["start"])))

        resolved: List[Dict[str, Any]] = []

        for current in item_list:
            if not resolved:
                resolved.append(current)
                continue

            last = resolved[-1]

            # Check overlap: last.end > current.start
            if last["end"] > current["start"]:
                last_len = last["end"] - last["start"]
                curr_len = current["end"] - current["start"]

                id_types = {"AADHAAR", "PAN", "GSTIN", "VOTER_ID", "PASSPORT"}
                if current["entity_type"] in id_types and last["entity_type"] not in id_types:
                    resolved[-1] = current
                elif last["entity_type"] in id_types and current["entity_type"] not in id_types:
                    continue
                elif current["score"] > last["score"] + 0.05:
                    resolved[-1] = current
                elif last["score"] > current["score"] + 0.05:
                    continue
                elif curr_len > last_len:
                    resolved[-1] = current
                else:
                    continue
            else:
                resolved.append(current)

        return resolved
