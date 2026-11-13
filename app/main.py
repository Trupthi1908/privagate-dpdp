"""FastAPI 5-Stage DPDP Privacy Gateway with Integrated API Sentinel & Section 12 DSR Engine."""

from __future__ import annotations

import io
import logging
import os
import re
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional
import requests
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("privagate.main")


def ensure_spacy_model(model_name: str = "en_core_web_sm") -> None:
    """Ensures that the specified spaCy model is available."""
    try:
        import spacy
        try:
            spacy.load(model_name)
            return
        except Exception:
            pass

        wheel_url = "https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl"
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--user", wheel_url],
            capture_output=True,
            text=True,
            check=False,
        )

        import site
        user_site = site.getusersitepackages()
        if user_site and user_site not in sys.path:
            sys.path.append(user_site)
    except Exception:
        pass


ensure_spacy_model("en_core_web_sm")

# Hugging Face API Configuration
HUGGINGFACE_API_TOKEN = os.getenv("HUGGINGFACE_API_TOKEN", "")
HF_HEADERS = {"Authorization": f"Bearer {HUGGINGFACE_API_TOKEN}"} if HUGGINGFACE_API_TOKEN else {}
HF_TROCR_URL = "https://api-inference.huggingface.co/models/microsoft/trocr-base-printed"
HF_LLAMA3_URL = "https://api-inference.huggingface.co/models/meta-llama/Meta-Llama-3-8B-Instruct"

from app.database import (
    erase_entity_records,
    get_audit_logs,
    get_audit_stats,
    get_dsr_logs,
    init_db,
    log_request,
    save_vault_mappings,
)
from app.detector import PIIDetectionEngine
from app.llm_router import LLMRouter
from app.reinsert import SafeReinsertEngine
from app.sentinel import APISentinel
from app.tokenizer import PURPOSE_BLOCKED_ENTITIES, ConsistentTokenizer
from app.validator import validate_document_anomalies

app = FastAPI(
    title="PrivaGate - DPDP Enterprise Privacy Gateway & API Sentinel",
    version="2.1.0",
    description="Compliant with the Digital Personal Data Protection Act, 2023 & Rules, 2025",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize engines
sentinel = APISentinel()
detector = PIIDetectionEngine()
tokenizer = ConsistentTokenizer()
llm_router = LLMRouter()
reinsert_engine = SafeReinsertEngine()

# Ensure SQLite schema is ready
init_db()


class GatewayRequest(BaseModel):
    text: str = Field(..., description="Raw enterprise document text containing sensitive personal data")
    task: str = Field("summarize", description="Task: 'summarize' or 'extract'")
    purpose: str = Field(
        "general",
        description="DPDP Consent Purpose: 'general', 'kyc_processing', 'loan_underwriting', 'marketing', 'customer_support'",
    )
    llm_provider: str = Field("local_slm", description="Provider: 'gemini', 'openai', or 'local_slm'")
    format_preserving: bool = Field(
        False, description="Whether to generate synthetic format-preserving dummy tokens (FPT)"
    )


class GatewayResponse(BaseModel):
    request_id: str
    sentinel_status: str
    sentinel_risk_score: int
    sentinel_threats: List[str]
    original_text: str
    sanitized_text: str
    outbound_payload: str
    detected_entities: List[Dict[str, Any]]
    detected_types: List[str]
    entity_count: int
    blocked_entities: List[Dict[str, Any]]
    raw_llm_response: str
    final_response: str
    external_model_used: str
    outbound_leakage_count: int
    reinsertion_accuracy: float
    gateway_latency_ms: float
    reinsertion_metrics: Dict[str, Any]
    placeholder_map: Dict[str, str] = Field(default_factory=dict)


class DSRErasureRequest(BaseModel):
    identifier: str = Field(..., description="Target name, national ID, placeholder, or request ID to purge")
    reason: str = Field(
        "Section 12 DPDP Right to Erasure Request",
        description="Reason for erasure under DPDP Act 2023",
    )


class ParseDocumentResponse(BaseModel):
    status: str = Field("success", description="Status of document parsing")
    filename: str = Field(..., description="Original filename of the uploaded file")
    page_count: int = Field(1, description="Number of pages parsed from document")
    character_count: int = Field(0, description="Extracted text character length")
    word_count: int = Field(0, description="Extracted text word count")
    extracted_text: str = Field(..., description="Extracted plain text content")


class ExtractTextResponse(BaseModel):
    status: str = Field("success", description="Status of OCR extraction")
    filename: str = Field(..., description="Original filename of the uploaded image")
    model: str = Field("microsoft/trocr-base-printed", description="Hugging Face TrOCR model used")
    character_count: int = Field(0, description="Extracted text character length")
    word_count: int = Field(0, description="Extracted text word count")
    extracted_text: str = Field(..., description="Extracted plain text content")


class SecureChatRequest(BaseModel):
    message: str = Field(..., description="User prompt or question")
    document_text: Optional[str] = Field(None, description="Active document text from Tab 1")
    active_document_text: Optional[str] = Field(None, description="Direct active_document_text field")
    context_document: Optional[str] = Field(None, description="Alternative field for document context")
    context: Optional[str] = Field(None, description="Alternative context field")
    chat_history: Optional[List[Dict[str, str]]] = Field(default_factory=list, description="Session chat history")
    purpose: str = Field("loan_underwriting", description="DPDP Consent Purpose")
    llm_provider: str = Field("huggingface", description="Provider: 'huggingface' (Llama-3), 'local_slm', 'gemini', or 'openai'")
    format_preserving: bool = Field(False, description="Whether to use format-preserving tokenization")


class SecureChatResponse(BaseModel):
    request_id: str
    sentinel_status: str
    sentinel_risk_score: int
    sentinel_threats: List[str]
    user_message: str
    sanitized_user_message: str
    outbound_payload: str
    detected_entities: List[Dict[str, Any]]
    placeholder_map: Dict[str, str]
    raw_llm_response: str
    final_response: str
    compliance_audit: Dict[str, Any] = Field(default_factory=dict)
    detected_anomalies: List[Dict[str, Any]] = Field(default_factory=list, description="Automated document error and anomaly checks")
    anomalies_count: int = Field(0, description="Total count of detected errors and anomalies")
    external_model_used: str
    outbound_leakage_count: int
    reinsertion_accuracy: float
    gateway_latency_ms: float


class ChatGatewayRequest(BaseModel):
    message: str = Field(..., description="User message or query")
    context_document: Optional[str] = Field(None, description="Optional attached document context")
    chat_history: Optional[List[Dict[str, str]]] = Field(default_factory=list, description="Prior conversation turns")
    purpose: str = Field("customer_support", description="DPDP Consent Purpose")
    llm_provider: str = Field("local_slm", description="Provider: 'gemini', 'openai', or 'local_slm'")
    format_preserving: bool = Field(False, description="Whether to use format-preserving tokenization")


class ChatGatewayResponse(BaseModel):
    request_id: str
    sentinel_status: str
    sentinel_risk_score: int
    sentinel_threats: List[str]
    user_message: str
    sanitized_user_message: str
    outbound_payload: str
    detected_entities: List[Dict[str, Any]]
    placeholder_map: Dict[str, str]
    raw_llm_response: str
    final_response: str
    external_model_used: str
    outbound_leakage_count: int
    reinsertion_accuracy: float
    gateway_latency_ms: float


def extract_uploaded_file_text(filename: str, content_bytes: bytes) -> str:
    """Extracts text from PDF, DOCX, or TXT file bytes."""
    fname = filename.lower()
    if fname.endswith(".pdf"):
        import pypdf
        reader = pypdf.PdfReader(io.BytesIO(content_bytes))
        pages_text = [page.extract_text() or "" for page in reader.pages]
        return "\n\n".join(t.strip() for t in pages_text if t.strip())

    elif fname.endswith(".docx"):
        import docx
        doc = docx.Document(io.BytesIO(content_bytes))
        paras = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
        return "\n\n".join(paras)

    else:
        try:
            return content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return content_bytes.decode("latin-1")


@app.post("/api/v1/parse-document", response_model=ParseDocumentResponse)
async def parse_document(file: UploadFile = File(...)):
    """Extracts text dynamically from uploaded PDF files using pypdf.

    Also extracts text from TXT and DOCX files. Downstream chatbot and privacy pipeline
    strictly process this extracted document text.
    """
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded or filename missing.")

    fname = file.filename.lower()
    try:
        content_bytes = await file.read()
        if not content_bytes:
            raise HTTPException(status_code=400, detail=f"Uploaded file '{file.filename}' is empty (0 bytes).")

        page_count = 1
        if fname.endswith(".pdf"):
            import pypdf
            reader = pypdf.PdfReader(io.BytesIO(content_bytes))
            page_count = len(reader.pages)
            pages_text = [page.extract_text() or "" for page in reader.pages]
            extracted_text = "\n\n".join(t.strip() for t in pages_text if t.strip())
        elif fname.endswith(".docx"):
            import docx
            doc = docx.Document(io.BytesIO(content_bytes))
            paras = [p.text.strip() for p in doc.paragraphs if p.text.strip()]
            extracted_text = "\n\n".join(paras)
        else:
            try:
                extracted_text = content_bytes.decode("utf-8")
            except UnicodeDecodeError:
                extracted_text = content_bytes.decode("latin-1", errors="replace")

        extracted_text = extracted_text.strip()
        if not extracted_text:
            raise HTTPException(
                status_code=422,
                detail=f"Uploaded document '{file.filename}' contains no readable text.",
            )

        return ParseDocumentResponse(
            status="success",
            filename=file.filename,
            page_count=page_count,
            character_count=len(extracted_text),
            word_count=len(extracted_text.split()),
            extracted_text=extracted_text,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to parse document '{file.filename}': {str(e)}",
        )


def deskew_image(cv_img):
    """Detects text orientation and auto-deskews rotated documents using minimum area rectangle."""
    try:
        import cv2
        import numpy as np

        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY) if len(cv_img.shape) == 3 else cv_img
        coords = np.column_stack(np.where(gray < 200))
        if len(coords) < 50:
            return cv_img
        rect = cv2.minAreaRect(coords)
        angle = rect[-1]
        if angle < -45:
            angle = -(90 + angle)
        else:
            angle = -angle
        if 0.5 < abs(angle) < 45:
            (h, w) = cv_img.shape[:2]
            center = (w // 2, h // 2)
            M = cv2.getRotationMatrix2D(center, angle, 1.0)
            return cv2.warpAffine(cv_img, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
        return cv_img
    except Exception:
        return cv_img


def preprocess_image_for_ocr(image_bytes: bytes) -> bytes:
    """Preprocesses uploaded document image with OpenCV:
    1. Deskewing to fix rotated camera photos.
    2. Grayscale conversion.
    3. Contrast enhancement via CLAHE (Contrast Limited Adaptive Histogram Equalization).
    4. Noise reduction using OpenCV (fastNlMeansDenoising).
    Returns enhanced PNG byte stream.
    """
    try:
        import cv2
        import numpy as np

        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return image_bytes

        # 1. Auto-deskew
        img = deskew_image(img)

        # 2. Grayscale conversion
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

        # 3. Contrast enhancement via CLAHE
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8))
        contrast_enhanced = clahe.apply(gray)

        # 4. Noise reduction
        denoised = cv2.fastNlMeansDenoising(contrast_enhanced, h=10)

        success, encoded = cv2.imencode(".png", denoised)
        if success:
            return encoded.tobytes()
        return image_bytes
    except Exception as e:
        logger.warning(f"OpenCV image preprocessing skipped or failed: {e}")
        return image_bytes


def preprocess_for_handwriting(image_bytes: bytes) -> bytes:
    """Preprocesses handwritten reports and complex noisy scans:
    1. Auto-deskews orientation.
    2. Converts to grayscale.
    3. CLAHE contrast enhancement for faint pencil/blue ink.
    4. Adaptive Gaussian thresholding to binarize ink strokes and isolate handwriting from paper textures.
    """
    try:
        import cv2
        import numpy as np

        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        if img is None:
            return image_bytes

        img = deskew_image(img)
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        clahe = cv2.createCLAHE(clipLimit=2.5, tileGridSize=(8, 8))
        enhanced = clahe.apply(gray)
        thresh = cv2.adaptiveThreshold(enhanced, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 17, 9)

        success, encoded = cv2.imencode(".png", thresh)
        return encoded.tobytes() if success else image_bytes
    except Exception:
        return image_bytes


def parse_indian_document_fields(text: str, filename: str = "") -> Dict[str, Any]:
    """Fallback regex parser for Indian financial IDs (Aadhaar, PAN, application IDs),
    applicant names, course, and loan amounts to correct vision model numerical misalignment
    and ensure structured key-value extraction for government forms (like PM-Vidyalaxmi CELAF).
    """
    clean = (text or "").strip()

    # 1. Application ID / CELAF Reference
    app_id = None
    m_celaf = re.search(r"\b(?:CELAF|PV|PMV|APP)[\-_][A-Za-z0-9\-_/]{4,25}\b", clean, re.IGNORECASE)
    if m_celaf:
        app_id = m_celaf.group(0).strip()
    else:
        app_m = re.search(
            r"(?i)(?:application\s*(?:id|no|num|number|ref(?:erence)?)|celaf\s*(?:id|no|ref)?|pm[\s\-_]?vidyalaxmi\s*(?:id|no|ref)?)\s*[:\-]?\s*([A-Za-z0-9\-_/]+)",
            clean,
        )
        if app_m:
            app_id = app_m.group(1).strip()

    # 2. Aadhaar Number (Standard 12 digits or masked)
    aadhaar = None
    aad_m = re.search(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b", clean)
    if aad_m:
        aadhaar = aad_m.group(0).strip()
    else:
        mask_m = re.search(r"\b(?:[xX]{4}[\s-]?){2}\d{4}\b", clean)
        if mask_m:
            aadhaar = mask_m.group(0).strip()

    # 3. PAN
    pan = None
    pan_m = re.search(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", clean)
    if pan_m:
        pan = pan_m.group(0).strip()

    # 4. Applicant / Student Name
    applicant_name = None
    name_m = re.search(
        r"(?i)\b(?:applicant|student|borrower)(?:\s*(?:full)?\s*name)?\b\s*[:\-]?[ \t]+([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,3})",
        clean,
    )
    if name_m:
        applicant_name = name_m.group(1).strip()
    else:
        name_m2 = re.search(
            r"(?i)(?:applicant(?:\s*full)?\s*name|student(?:\s*full)?\s*name|borrower(?:\s*full)?\s*name|name\s*of\s*(?:applicant|student))\s*[:\-]?\s*([A-Za-z\s\.\-_]+)",
            clean,
        )
        if name_m2:
            applicant_name = name_m2.group(1).strip()

    # 5. Course / Degree / Academic Program
    course = None
    course_m = re.search(
        r"(?i)(?:course(?:\s*(?:name|of\s*study))?|\bdegree\b|\bacademic\s*program\b|\bprogram\b)(?:\s*/\s*degree)?\s*[:\-]?\s*([^\n\r,;]+)",
        clean,
    )
    if course_m:
        val = course_m.group(1).strip()
        val = re.sub(r"^[\*\s:]+", "", val).strip()
        val = re.sub(r"\s+(?:INR|Rs\.?|₹).*$", "", val, flags=re.IGNORECASE).strip()
        if len(val) > 1 and "not " not in val.lower():
            course = val
    if not course:
        deg_m = re.search(
            r"\b(?:B\.?Tech|B\.?E\.?|M\.?Tech|M\.?E\.?|MBBS|BDS|B\.?Sc|M\.?Sc|MBA|BBA|BCA|MCA|B\.?Com|Ph\.?D)\b(?:\s+(?:in\s+)?[A-Za-z\s]+)?",
            clean,
            re.IGNORECASE,
        )
        if deg_m:
            course = deg_m.group(0).strip()
            course = re.sub(r"\s+(?:INR|Rs\.?|₹).*$", "", course, flags=re.IGNORECASE).strip()

    # 6. Loan Amount
    loan_amount = None
    amt_m = re.search(
        r"(?i)(?:loan\s*(?:amount|facility)(?:\s*requested|\s*sanctioned)?|sanction(?:ed)?\s*amount|requested\s*amount|course\s*fee|tuition\s*fee|total\s*amount)\s*[:\-]?\s*((?:Rs\.?|INR|₹)\s*[\d,]+(?:\.\d{1,2})?|\b[\d,]{4,12}\b)",
        clean,
    )
    if amt_m:
        loan_amount = amt_m.group(1).strip()
    else:
        curr_m = re.search(r"(?:Rs\.?|INR|₹)\s*[\d,]+(?:\.\d{1,2})?", clean)
        if curr_m:
            loan_amount = curr_m.group(0).strip()

    # 7. Form Type & Ministry Header
    is_celaf = any(k in clean.lower() or k in filename.lower() for k in ["celaf", "vidyalaxmi", "vidya lakshmi", "pm-vidyalaxmi"])
    ministry = "Department of Higher Education, Ministry of Education, Government of India" if is_celaf else None
    form_type = "PM-Vidyalaxmi Common Education Loan Application Form (CELAF)" if is_celaf else None

    return {
        "form_type": form_type,
        "ministry": ministry,
        "application_id": app_id,
        "applicant_name": applicant_name,
        "aadhaar": aadhaar,
        "pan": pan,
        "course": course,
        "loan_amount": loan_amount,
    }


@app.post("/api/v1/extract-text", response_model=ExtractTextResponse)
async def extract_text_from_image(file: UploadFile = File(...)):
    """Advanced Multi-Tier Vision & OCR Intake for printed documents, handwritten applications,
    medical reports, and complex noisy scans:
    - Tier 1: Multimodal Vision AI (Gemini 2.5 Flash Vision) when GEMINI_API_KEY is configured.
    - Tier 2: Local Dual-Pass RapidOCR (ONNX Runtime): Pass A on raw/contrast-enhanced image,
              Pass B on adaptive Gaussian binarized handwriting ink image.
    - Tier 3: OCR.space Engine 2 Cloud API (specialized deep-learning engine for handwriting & rotation).
    - Tier 4: Image EXIF & embedded text metadata.
    """
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No image file uploaded or filename missing.")

    try:
        image_bytes = await file.read()
        if not image_bytes:
            raise HTTPException(status_code=400, detail=f"Uploaded image '{file.filename}' is empty (0 bytes).")

        extracted_text = ""
        model_used = "RapidOCR-ONNX (Dual-Pass Handwriting Engine)"

        # Tier 1: Multimodal Vision AI (Gemini 2.5 Flash Vision)
        gemini_key = os.getenv("GEMINI_API_KEY")
        if gemini_key:
            try:
                from google import genai
                from google.genai import types

                client = genai.Client(api_key=gemini_key)
                mime = "image/png" if file.filename.lower().endswith(".png") else "image/jpeg"
                resp = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=[
                        types.Part.from_bytes(data=image_bytes, mime_type=mime),
                        (
                            "You are an expert document OCR and transcription system. "
                            "Transcribe all text, numbers, handwriting, forms, medical terms, headers, and labels "
                            "in this image accurately and comprehensively. Preserve original lines and field names. "
                            "Return ONLY the extracted document text without conversational filler."
                        ),
                    ],
                )
                if resp and resp.text and resp.text.strip():
                    extracted_text = resp.text.strip()
                    model_used = "Gemini 2.5 Flash Vision (Multimodal AI)"
            except Exception as e:
                logger.warning(f"Tier 1 Gemini Vision inference error: {e}")

        # Tier 2: Local Dual-Pass RapidOCR (Pass A: Raw, Pass B: Handwriting Adaptive Binarized)
        if not extracted_text:
            try:
                from rapidocr_onnxruntime import RapidOCR

                engine = RapidOCR()

                # Pass A: Raw Image
                res_raw, _ = engine(image_bytes)
                lines_raw = [item[1].strip() for item in res_raw if item[1] and item[1].strip()] if res_raw else []

                # Pass B: Handwriting Adaptive Preprocessed Image
                prep_bytes = preprocess_for_handwriting(image_bytes)
                res_prep, _ = engine(prep_bytes)
                lines_prep = [item[1].strip() for item in res_prep if item[1] and item[1].strip()] if res_prep else []

                # Select richer set
                if len(lines_prep) > len(lines_raw):
                    extracted_text = "\n".join(lines_prep).strip()
                elif len(lines_raw) > 0:
                    extracted_text = "\n".join(lines_raw).strip()

                if extracted_text:
                    model_used = "RapidOCR-ONNX (Dual-Pass Handwriting Engine)"
            except Exception as e:
                logger.warning(f"Tier 2 RapidOCR inference error: {e}")

        # Tier 3: OCR.space Cloud OCR Engine 2 (Handwriting & Skewed Documents)
        if not extracted_text or len(extracted_text.split()) < 3:
            try:
                r = requests.post(
                    "https://api.ocr.space/parse/image",
                    files={"filename": (file.filename, image_bytes, "image/png")},
                    data={
                        "apikey": "helloworld",
                        "language": "eng",
                        "OCREngine": "2",
                        "scale": "true",
                        "detectOrientation": "true",
                    },
                    timeout=12,
                )
                if r.status_code == 200:
                    data = r.json()
                    cloud_lines = []
                    for pr in data.get("ParsedResults", []):
                        pt = pr.get("ParsedText", "").strip()
                        if pt:
                            cloud_lines.append(pt)
                    cand = "\n".join(cloud_lines).strip()
                    if len(cand.split()) > len(extracted_text.split()):
                        extracted_text = cand
                        model_used = "OCR.space Engine 2 (Handwriting Deep Learning)"
            except Exception:
                pass

        # Tier 4: Image EXIF / text metadata
        if not extracted_text:
            try:
                from PIL import Image

                img = Image.open(io.BytesIO(image_bytes))
                meta_txt = img.info.get("text") or img.info.get("Description") or ""
                if meta_txt.strip():
                    extracted_text = meta_txt.strip()
                    model_used = "Image Metadata / EXIF"
            except Exception:
                pass

        if extracted_text.strip():
            extracted_text = re.sub(r"\[Note:.*?\]\s*", "", extracted_text).strip()
        else:
            extracted_text = (
                f"DOCUMENT IMAGE INTAKE: {file.filename}\n"
                f"No legible text or handwriting could be extracted from this image. "
                f"Please ensure the document image is clear, well-lit, and contains printed or legible handwritten text."
            )

        return ExtractTextResponse(
            status="success",
            filename=file.filename,
            model=model_used,
            character_count=len(extracted_text),
            word_count=len(extracted_text.split()),
            extracted_text=extracted_text,
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to perform Image-to-Text OCR on '{file.filename}': {str(e)}",
        )


@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "PrivaGate & API Sentinel Backend",
        "docs": "/docs",
    }


@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "gateway": "PrivaGate DPDP-Ready Engine",
        "sentinel": "Active & Monitoring",
        "compliance": "DPDP Act 2023 / DPDP Rules 2025",
        "dsr_engine": "Ready (Section 12 Right to Erasure)",
    }


@app.post("/api/v1/gateway/process", response_model=GatewayResponse)
def process_gateway_request(req: GatewayRequest):
    t_start = time.perf_counter()

    # Stage 0: API Sentinel Inbound Guard
    sentinel_in = sentinel.inspect_inbound(req.text)
    if sentinel_in.status == "BLOCKED":
        rec_id = log_request(
            request_type=req.task,
            purpose=req.purpose,
            detected_entity_types=[],
            entity_count=0,
            sanitized_payload="[REQUEST_BLOCKED_BY_API_SENTINEL]",
            external_model_used="none (blocked)",
            leakage_count=0,
            reinsertion_accuracy=0.0,
            gateway_latency_ms=sentinel_in.latency_ms,
            sentinel_status="BLOCKED",
            sentinel_risk_score=sentinel_in.risk_score,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Security Alert: Request blocked by API Sentinel.",
                "request_id": rec_id,
                "threats_detected": sentinel_in.detected_threats,
                "risk_score": sentinel_in.risk_score,
            },
        )

    # Stage 1: Detect PII
    detected_entities = detector.detect(req.text)

    # Stage 2: Mask & Tokenize (with FPT & Section 6 Purpose Policy)
    token_res = tokenizer.mask(
        text=req.text,
        detected_entities=detected_entities,
        purpose=req.purpose,
        format_preserving=req.format_preserving,
    )

    # Stage 2.5: API Sentinel Outbound Zero-Leakage Firewall
    sentinel_out = sentinel.verify_outbound_payload(
        sanitized_text=token_res.sanitized_text,
        placeholder_map=token_res.placeholder_map,
        blocked_entities=token_res.blocked_entities,
    )

    # Stage 3: Forward to LLM
    llm_res = llm_router.route(
        sanitized_text=token_res.sanitized_text,
        task=req.task,
        provider=req.llm_provider,
    )

    # Stage 4: Reinsert locally
    reinsert_res = reinsert_engine.reinsert(
        llm_output=llm_res.text,
        placeholder_map=token_res.placeholder_map,
    )

    t_end = time.perf_counter()
    gateway_latency_ms = round((t_end - t_start) * 1000.0, 2)

    # Record telemetry in Sentinel
    sentinel.record_metrics(
        entity_count=token_res.entity_count,
        is_fallback=llm_res.is_fallback,
    )

    # Log to SQLite Audit Trail
    rec_id = log_request(
        request_type=req.task,
        purpose=req.purpose,
        detected_entity_types=token_res.detected_types,
        entity_count=token_res.entity_count,
        sanitized_payload=token_res.sanitized_text,
        external_model_used=f"{llm_res.provider}:{llm_res.model_name}",
        leakage_count=sentinel_out.leakage_count,
        reinsertion_accuracy=reinsert_res.reinsertion_accuracy,
        gateway_latency_ms=gateway_latency_ms,
        sentinel_status=sentinel_in.status,
        sentinel_risk_score=sentinel_in.risk_score,
    )

    # Save isolated local cryptographic mappings in the local vault table
    if token_res.placeholder_map:
        save_vault_mappings(rec_id, token_res.placeholder_map, detected_entities)

    return GatewayResponse(
        request_id=rec_id,
        sentinel_status=sentinel_in.status,
        sentinel_risk_score=sentinel_in.risk_score,
        sentinel_threats=sentinel_in.detected_threats,
        original_text=req.text,
        sanitized_text=token_res.sanitized_text,
        outbound_payload=llm_res.outbound_payload,
        detected_entities=detected_entities,
        detected_types=token_res.detected_types,
        entity_count=token_res.entity_count,
        blocked_entities=token_res.blocked_entities,
        raw_llm_response=llm_res.text,
        final_response=reinsert_res.restored_text,
        external_model_used=f"{llm_res.provider}:{llm_res.model_name}",
        outbound_leakage_count=sentinel_out.leakage_count,
        reinsertion_accuracy=reinsert_res.reinsertion_accuracy,
        gateway_latency_ms=gateway_latency_ms,
        reinsertion_metrics=reinsert_res.metrics,
        placeholder_map=token_res.placeholder_map,
    )


@app.post("/api/v1/gateway/process-file", response_model=GatewayResponse)
def process_file_gateway_request(
    file: UploadFile = File(...),
    task: str = Form("summarize"),
    purpose: str = Form("general"),
    llm_provider: str = Form("local_slm"),
    format_preserving: bool = Form(False),
):
    content = file.file.read()
    extracted_text = extract_uploaded_file_text(file.filename or "uploaded.txt", content)

    req = GatewayRequest(
        text=extracted_text,
        task=task,
        purpose=purpose,
        llm_provider=llm_provider,
        format_preserving=format_preserving,
    )
    return process_gateway_request(req)


@app.post("/api/v1/secure-chat", response_model=SecureChatResponse)
def secure_chat_endpoint(req: SecureChatRequest):
    """Processes conversational queries with active document context through the 4-stage DPDP Privacy Gateway.

    Instructs the LLM to both answer user queries and actively scan the document text
    for compliance errors, inconsistencies, or risk factors (invalid ID formats, missing data, etc.),
    with guaranteed zero outbound raw PII leakage and local cryptographic reinsertion.
    """
    t_start = time.perf_counter()

    raw_doc = (
        req.document_text
        or req.active_document_text
        or req.context_document
        or req.context
        or ""
    ).strip()

    # Dynamically read whatever text is present in document_text from frontend payload
    doc_text = raw_doc
    full_inbound = f"{doc_text}\n\nUser Question:\n{req.message}".strip() if doc_text else req.message

    # Stage 0: API Sentinel Inbound Guard
    sentinel_in = sentinel.inspect_inbound(full_inbound)
    if sentinel_in.status == "BLOCKED":
        rec_id = log_request(
            request_type="secure_chat",
            purpose=req.purpose,
            detected_entity_types=[],
            entity_count=0,
            sanitized_payload="[CHAT_BLOCKED_BY_API_SENTINEL]",
            external_model_used="none (blocked)",
            leakage_count=0,
            reinsertion_accuracy=0.0,
            gateway_latency_ms=sentinel_in.latency_ms,
            sentinel_status="BLOCKED",
            sentinel_risk_score=sentinel_in.risk_score,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Security Alert: Inbound chat message blocked by API Sentinel.",
                "request_id": rec_id,
                "threats_detected": sentinel_in.detected_threats,
                "risk_score": sentinel_in.risk_score,
            },
        )

    # Stage 1: Detect PII across message and context
    detected_entities = detector.detect(full_inbound)

    # Stage 2: Mask & Tokenize with Purpose Binding
    token_res = tokenizer.mask(
        text=full_inbound,
        detected_entities=detected_entities,
        purpose=req.purpose,
        format_preserving=req.format_preserving,
    )

    if doc_text:
        sanitized_doc = tokenizer.mask(
            text=doc_text,
            detected_entities=detector.detect(doc_text),
            purpose=req.purpose,
            format_preserving=req.format_preserving,
        ).sanitized_text
        sanitized_msg = tokenizer.mask(
            text=req.message,
            detected_entities=detector.detect(req.message),
            purpose=req.purpose,
            format_preserving=req.format_preserving,
        ).sanitized_text
    else:
        sanitized_doc = None
        sanitized_msg = token_res.sanitized_text

    # Stage 2.5: API Sentinel Outbound Zero-Leak Firewall
    sentinel_out = sentinel.verify_outbound_payload(
        sanitized_text=token_res.sanitized_text,
        placeholder_map=token_res.placeholder_map,
        blocked_entities=token_res.blocked_entities,
    )

    # Stage 3: Forward to LLM Router in Secure Chat Mode (Answer User + Audit Compliance & Risks)
    llm_res = llm_router.secure_chat(
        sanitized_user_message=sanitized_msg,
        sanitized_context=sanitized_doc,
        chat_history=req.chat_history,
        provider=req.llm_provider,
    )

    # Stage 4: Reinsert locally
    reinsert_res = reinsert_engine.reinsert(
        llm_output=llm_res.text,
        placeholder_map=token_res.placeholder_map,
    )

    t_end = time.perf_counter()
    latency_ms = round((t_end - t_start) * 1000.0, 2)

    sentinel.record_metrics(
        entity_count=token_res.entity_count,
        is_fallback=llm_res.is_fallback,
    )

    # SQLite Audit Trail
    rec_id = log_request(
        request_type="secure_chat",
        purpose=req.purpose,
        detected_entity_types=token_res.detected_types,
        entity_count=token_res.entity_count,
        sanitized_payload=token_res.sanitized_text,
        external_model_used=f"{llm_res.provider}:{llm_res.model_name}",
        leakage_count=sentinel_out.leakage_count,
        reinsertion_accuracy=reinsert_res.reinsertion_accuracy,
        gateway_latency_ms=latency_ms,
        sentinel_status=sentinel_in.status,
        sentinel_risk_score=sentinel_in.risk_score,
    )

    if token_res.placeholder_map:
        save_vault_mappings(rec_id, token_res.placeholder_map, detected_entities)

    # Run Automated Document Error & Anomaly Validation
    doc_anomalies = validate_document_anomalies(doc_text) if doc_text else []
    compliance_audit = llm_router.audit_document_compliance(doc_text or req.message)
    compliance_audit["detected_anomalies"] = doc_anomalies
    compliance_audit["anomalies_count"] = len(doc_anomalies)

    return SecureChatResponse(
        request_id=rec_id,
        sentinel_status=sentinel_in.status,
        sentinel_risk_score=sentinel_in.risk_score,
        sentinel_threats=sentinel_in.detected_threats,
        user_message=req.message,
        sanitized_user_message=sanitized_msg,
        outbound_payload=llm_res.outbound_payload,
        detected_entities=detected_entities,
        placeholder_map=token_res.placeholder_map,
        raw_llm_response=llm_res.text,
        final_response=reinsert_res.restored_text,
        compliance_audit=compliance_audit,
        detected_anomalies=doc_anomalies,
        anomalies_count=len(doc_anomalies),
        external_model_used=f"{llm_res.provider}:{llm_res.model_name}",
        outbound_leakage_count=sentinel_out.leakage_count,
        reinsertion_accuracy=reinsert_res.reinsertion_accuracy,
        gateway_latency_ms=latency_ms,
    )


@app.post("/api/v1/chat/process", response_model=ChatGatewayResponse)
def process_chat_message(req: ChatGatewayRequest):
    """Processes conversational queries through the 4-stage DPDP Privacy Gateway:

    Detect -> Mask -> Forward -> Reinsert with zero outbound raw PII leakage.
    """
    t_start = time.perf_counter()

    full_inbound = f"{req.context_document or ''}\n{req.message}".strip()

    # Stage 0: API Sentinel Inbound Guard
    sentinel_in = sentinel.inspect_inbound(full_inbound)
    if sentinel_in.status == "BLOCKED":
        rec_id = log_request(
            request_type="chat",
            purpose=req.purpose,
            detected_entity_types=[],
            entity_count=0,
            sanitized_payload="[CHAT_BLOCKED_BY_API_SENTINEL]",
            external_model_used="none (blocked)",
            leakage_count=0,
            reinsertion_accuracy=0.0,
            gateway_latency_ms=sentinel_in.latency_ms,
            sentinel_status="BLOCKED",
            sentinel_risk_score=sentinel_in.risk_score,
        )
        raise HTTPException(
            status_code=403,
            detail={
                "message": "Security Alert: Inbound chat message blocked by API Sentinel.",
                "request_id": rec_id,
                "threats_detected": sentinel_in.detected_threats,
                "risk_score": sentinel_in.risk_score,
            },
        )

    # Stage 1: Detect PII across message and context
    detected_entities = detector.detect(full_inbound)

    # Stage 2: Mask & Tokenize with Purpose Binding
    token_res = tokenizer.mask(
        text=full_inbound,
        detected_entities=detected_entities,
        purpose=req.purpose,
        format_preserving=req.format_preserving,
    )

    if req.context_document:
        sanitized_context = tokenizer.mask(
            text=req.context_document,
            detected_entities=detector.detect(req.context_document),
            purpose=req.purpose,
            format_preserving=req.format_preserving,
        ).sanitized_text
        sanitized_msg = tokenizer.mask(
            text=req.message,
            detected_entities=detector.detect(req.message),
            purpose=req.purpose,
            format_preserving=req.format_preserving,
        ).sanitized_text
    else:
        sanitized_context = None
        sanitized_msg = token_res.sanitized_text

    # Stage 2.5: API Sentinel Outbound Zero-Leak Firewall
    sentinel_out = sentinel.verify_outbound_payload(
        sanitized_text=token_res.sanitized_text,
        placeholder_map=token_res.placeholder_map,
        blocked_entities=token_res.blocked_entities,
    )

    # Stage 3: Forward to LLM Router in Chat Mode
    llm_res = llm_router.chat(
        sanitized_user_message=sanitized_msg,
        sanitized_context=sanitized_context,
        chat_history=req.chat_history,
        provider=req.llm_provider,
    )

    # Stage 4: Reinsert locally
    reinsert_res = reinsert_engine.reinsert(
        llm_output=llm_res.text,
        placeholder_map=token_res.placeholder_map,
    )

    t_end = time.perf_counter()
    latency_ms = round((t_end - t_start) * 1000.0, 2)

    sentinel.record_metrics(
        entity_count=token_res.entity_count,
        is_fallback=llm_res.is_fallback,
    )

    # SQLite Audit Trail
    rec_id = log_request(
        request_type="chat",
        purpose=req.purpose,
        detected_entity_types=token_res.detected_types,
        entity_count=token_res.entity_count,
        sanitized_payload=token_res.sanitized_text,
        external_model_used=f"{llm_res.provider}:{llm_res.model_name}",
        leakage_count=sentinel_out.leakage_count,
        reinsertion_accuracy=reinsert_res.reinsertion_accuracy,
        gateway_latency_ms=latency_ms,
        sentinel_status=sentinel_in.status,
        sentinel_risk_score=sentinel_in.risk_score,
    )

    if token_res.placeholder_map:
        save_vault_mappings(rec_id, token_res.placeholder_map, detected_entities)

    return ChatGatewayResponse(
        request_id=rec_id,
        sentinel_status=sentinel_in.status,
        sentinel_risk_score=sentinel_in.risk_score,
        sentinel_threats=sentinel_in.detected_threats,
        user_message=req.message,
        sanitized_user_message=sanitized_msg,
        outbound_payload=llm_res.outbound_payload,
        detected_entities=detected_entities,
        placeholder_map=token_res.placeholder_map,
        raw_llm_response=llm_res.text,
        final_response=reinsert_res.restored_text,
        external_model_used=f"{llm_res.provider}:{llm_res.model_name}",
        outbound_leakage_count=sentinel_out.leakage_count,
        reinsertion_accuracy=reinsert_res.reinsertion_accuracy,
        gateway_latency_ms=latency_ms,
    )


@app.post("/api/v1/rights/erase")
def erase_data_subject_rights(req: DSRErasureRequest):
    """Section 12 DPDP Right to be Forgotten (Data Subject Rights - DSR Erasure):

    Purges all matching local cryptographic vault records across the system and logs an erasure certificate.
    """
    if not req.identifier or len(req.identifier.strip()) < 2:
        raise HTTPException(status_code=400, detail="Identifier must be at least 2 characters.")

    result = erase_entity_records(req.identifier, reason=req.reason)
    return result


@app.get("/api/v1/rights/logs")
def get_dsr_erasure_ledger(limit: int = Query(50, ge=1, le=200)):
    lim = limit if isinstance(limit, int) else 50
    return {"erasure_records": get_dsr_logs(limit=lim)}


@app.get("/api/v1/sentinel/stats")
def get_sentinel_diagnostics():
    return sentinel.get_sentinel_stats()


@app.get("/api/v1/audit/logs")
def get_logs(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    lim = limit if isinstance(limit, int) else 50
    off = offset if isinstance(offset, int) else 0
    logs = get_audit_logs(limit=lim, offset=off)
    return {"logs": logs, "count": len(logs)}


@app.get("/api/v1/audit/stats")
def get_stats():
    return get_audit_stats()


@app.post("/api/v1/eval/run")
def trigger_evaluation():
    try:
        from eval.evaluate import run_full_evaluation
        report = run_full_evaluation()
        return report
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {str(e)}")
