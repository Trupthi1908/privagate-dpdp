"""Generate high-resolution sample document images for PrivaGate DPDP Image Intake testing.
Produces:
1. sample_documents/pm_vidyalaxmi_celaf_application.png
2. sample_documents/aadhaar_kyc_verification_card.png
3. sample_documents/loan_sanction_letter.png
"""

import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIR = Path("sample_documents")
OUTPUT_DIR.mkdir(exist_ok=True)

def get_font(size: int, bold: bool = False):
    try:
        # Standard Windows fonts
        font_name = "arialbd.ttf" if bold else "arial.ttf"
        font_path = Path("C:/Windows/Fonts") / font_name
        if font_path.exists():
            return ImageFont.truetype(str(font_path), size)
        # Fallback to Segoe UI
        font_name_alt = "segoeuib.ttf" if bold else "segoeui.ttf"
        font_path_alt = Path("C:/Windows/Fonts") / font_name_alt
        if font_path_alt.exists():
            return ImageFont.truetype(str(font_path_alt), size)
    except Exception:
        pass
    return ImageFont.load_default()

def create_celaf_document():
    width = 1000
    height = 1300
    img = Image.new("RGB", (width, height), color="#F8FAFC")
    draw = ImageDraw.Draw(img)

    # Fonts
    f_title = get_font(24, bold=True)
    f_sub = get_font(15, bold=False)
    f_sec = get_font(16, bold=True)
    f_lbl = get_font(14, bold=True)
    f_val = get_font(14, bold=False)
    f_sm = get_font(12, bold=False)

    # Top Government Header Banner
    draw.rectangle([0, 0, width, 110], fill="#0F172A")
    draw.text((width // 2, 25), "GOVERNMENT OF INDIA", fill="#F8FAFC", font=f_title, anchor="mt")
    draw.text((width // 2, 58), "DEPARTMENT OF HIGHER EDUCATION — MINISTRY OF EDUCATION", fill="#94A3B8", font=f_sub, anchor="mt")
    draw.text((width // 2, 82), "PM-Vidyalaxmi Scheme: Common Education Loan Application Form (CELAF)", fill="#38BDF8", font=f_lbl, anchor="mt")

    # Outer Document Frame
    draw.rounded_rectangle([40, 130, width - 40, height - 50], radius=12, fill="#FFFFFF", outline="#CBD5E1", width=2)

    # Form Title
    draw.text((width // 2, 155), "APPLICATION FOR FINANCIAL ASSISTANCE (HIGHER EDUCATION LOAN)", fill="#1E293B", font=f_sec, anchor="mt")
    draw.line([(60, 185), (width - 60, 185)], fill="#E2E8F0", width=1)

    y = 205
    def draw_section_header(title: str, curr_y: int) -> int:
        draw.rounded_rectangle([60, curr_y, width - 60, curr_y + 32], radius=6, fill="#F1F5F9", outline="#E2E8F0", width=1)
        draw.text((75, curr_y + 7), title, fill="#0F172A", font=f_sec)
        return curr_y + 45

    def draw_row(fields: list, curr_y: int) -> int:
        col_w = (width - 120) // len(fields)
        for i, (label, val, highlight) in enumerate(fields):
            col_x = 60 + (i * col_w)
            draw.text((col_x + 10, curr_y), label, fill="#64748B", font=f_lbl)
            val_color = "#0369A1" if highlight else "#0F172A"
            draw.text((col_x + 10, curr_y + 20), val, fill=val_color, font=f_val)
        return curr_y + 50

    # Section 1: Application Metadata
    y = draw_section_header("1. APPLICATION REFERENCE & STATUS", y)
    y = draw_row([
        ("Application Reference ID:", "CELAF-2024-PV88419", True),
        ("Date of Submission:", "12-Nov-2024", False),
        ("Current Portal Status:", "Verified & Forwarded", False),
    ], y)

    # Section 2: Applicant Personal Details
    y = draw_section_header("2. APPLICANT IDENTIFICATION & NATIONAL KYC", y)
    y = draw_row([
        ("Applicant Full Name:", "Rohan Kolvekar", True),
        ("Date of Birth:", "14-Aug-2002", False),
        ("Gender:", "Male", False),
    ], y)
    y = draw_row([
        ("Aadhaar Number (UIDAI):", "4521 8832 9104", True),
        ("Permanent Account No (PAN):", "ABCDE1234F", True),
        ("Mobile Contact:", "+91 98765 43210", False),
    ], y)
    y = draw_row([
        ("Email Address:", "rohan.kolvekar@example.in", False),
        ("Permanent Residential Address:", "#42, 4th Cross, Indiranagar, Bengaluru, KA - 560038", False),
    ], y)

    # Section 3: Course & Institution Information
    y = draw_section_header("3. ACADEMIC PROGRAM & INSTITUTION ENROLLMENT", y)
    y = draw_row([
        ("Enrolled Institution:", "Indian Institute of Technology (IIT)", False),
        ("Course / Degree Program:", "B.Tech Computer Science and Engineering", True),
    ], y)
    y = draw_row([
        ("Academic Duration:", "4 Years (8 Semesters)", False),
        ("Academic Year:", "2024 - 2028", False),
        ("Admission Category:", "Merit / JEE Advanced Rank", False),
    ], y)

    # Section 4: Loan & Financial Facility Details
    y = draw_section_header("4. LOAN FACILITY & FINANCIAL ASSESSMENT", y)
    y = draw_row([
        ("Total Estimated Course Fee:", "INR 9,50,000", False),
        ("Own Contribution / Margin:", "INR 2,00,000", False),
        ("Requested Loan Amount:", "INR 7,50,000", True),
    ], y)
    y = draw_row([
        ("Lending Partner Bank:", "State Bank of India (Public Sector)", False),
        ("Moratorium Period:", "Course Duration + 1 Year", False),
        ("Interest Subsidy Scheme:", "Applicable under Central Govt Scheme", False),
    ], y)

    # Section 5: Verification & Compliance Badge
    y = draw_section_header("5. DIGITAL ATTESTATION & PRIVACY ASSURANCE", y)
    draw.rounded_rectangle([60, y, width - 60, y + 80], radius=8, fill="#ECFDF5", outline="#A7F3D0", width=1)
    draw.text((75, y + 12), "🛡️ VERIFIED UNDER DIGITAL PERSONAL DATA PROTECTION (DPDP) ACT 2023", fill="#065F46", font=f_lbl)
    draw.text((75, y + 36), "This official government intake document is authenticated by the Ministry of Education Central Portal.", fill="#047857", font=f_sm)
    draw.text((75, y + 54), "Downstream AI tokenization actively redacts Aadhaar, PAN, and identity identifiers prior to cloud transit.", fill="#047857", font=f_sm)

    # Footer
    draw.text((width // 2, height - 75), "Generated by PM-Vidyalaxmi Official Portal | Reference Copy | Confidential Record", fill="#94A3B8", font=f_sm, anchor="mt")

    out_path = OUTPUT_DIR / "pm_vidyalaxmi_celaf_application.png"
    img.save(out_path, format="PNG", dpi=(150, 150))
    print(f"Created: {out_path} ({width}x{height})")
    return out_path

def create_aadhaar_card():
    width = 900
    height = 560
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_gov = get_font(16, bold=True)
    f_sub = get_font(13, bold=False)
    f_sec = get_font(14, bold=True)
    f_aad = get_font(28, bold=True)
    f_lbl = get_font(13, bold=True)
    f_val = get_font(13, bold=False)
    f_tag = get_font(11, bold=True)

    # Outer Border
    draw.rounded_rectangle([20, 20, width - 20, height - 20], radius=16, fill="#FFFFFF", outline="#CBD5E1", width=2)

    # Header Bar
    draw.rectangle([22, 22, width - 22, 90], fill="#F8FAFC")
    draw.line([(22, 90), (width - 22, 90)], fill="#E2E8F0", width=1)
    draw.text((width // 2, 35), "GOVERNMENT OF INDIA", fill="#0F172A", font=f_gov, anchor="mt")
    draw.text((width // 2, 60), "Unique Identification Authority of India (UIDAI) — e-Aadhaar Verification Slip", fill="#475569", font=f_sub, anchor="mt")

    # Photo Box Mockup
    draw.rounded_rectangle([50, 120, 210, 320], radius=8, fill="#F1F5F9", outline="#CBD5E1", width=1)
    draw.text((130, 210), "[PHOTO]", fill="#94A3B8", font=f_sec, anchor="mm")
    draw.text((130, 235), "VERIFIED", fill="#10B981", font=f_tag, anchor="mm")

    # Details
    x = 240
    y = 125
    draw.text((x, y), "Name / नाम:", fill="#64748B", font=f_lbl)
    draw.text((x + 130, y), "Rohan Kolvekar", fill="#0F172A", font=f_sec)
    
    y += 38
    draw.text((x, y), "DOB / जन्म तिथि:", fill="#64748B", font=f_lbl)
    draw.text((x + 130, y), "14/08/2002", fill="#0F172A", font=f_val)

    y += 38
    draw.text((x, y), "Gender / लिंग:", fill="#64748B", font=f_lbl)
    draw.text((x + 130, y), "MALE / पुरुष", fill="#0F172A", font=f_val)

    y += 38
    draw.text((x, y), "Address / पता:", fill="#64748B", font=f_lbl)
    draw.text((x + 130, y), "#42, 4th Cross, Indiranagar, Bengaluru, Karnataka - 560038", fill="#0F172A", font=f_val)

    # Aadhaar Number Banner
    draw.rounded_rectangle([50, 360, width - 50, 450], radius=10, fill="#FEF2F2", outline="#FECACA", width=1)
    draw.text((width // 2, 375), "AADHAAR NUMBER / आधार संख्या", fill="#991B1B", font=f_sec, anchor="mt")
    draw.text((width // 2, 402), "4521  8832  9104", fill="#B91C1C", font=f_aad, anchor="mt")

    # Slogan Footer
    draw.rectangle([22, 480, width - 22, height - 22], fill="#F1F5F9")
    draw.text((width // 2, 498), "मेरा आधार, मेरी पहचान (Aadhaar - Proof of Identity, not Proof of Citizenship)", fill="#334155", font=f_sub, anchor="mt")

    out_path = OUTPUT_DIR / "aadhaar_kyc_verification_card.png"
    img.save(out_path, format="PNG", dpi=(150, 150))
    print(f"Created: {out_path} ({width}x{height})")
    return out_path

def create_loan_sanction_letter():
    width = 1000
    height = 1200
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_bank = get_font(22, bold=True)
    f_sub = get_font(14, bold=False)
    f_sec = get_font(16, bold=True)
    f_lbl = get_font(14, bold=True)
    f_val = get_font(14, bold=False)
    f_sm = get_font(12, bold=False)

    # Header
    draw.rectangle([0, 0, width, 100], fill="#1E3A8A")
    draw.text((60, 28), "STATE BANK OF INDIA", fill="#FFFFFF", font=f_bank)
    draw.text((60, 60), "Centralized Education Loan Processing Hub — Karnataka Circle", fill="#BFDBFE", font=f_sub)

    # Reference box
    y = 130
    draw.text((60, y), "SANCTION LETTER — HIGHER EDUCATION LOAN FACILITY", fill="#0F172A", font=f_sec)
    draw.line([(60, y + 28), (width - 60, y + 28)], fill="#CBD5E1", width=1)

    y += 45
    draw.text((60, y), "Sanction Reference: SBI/EL/2024/77412", fill="#64748B", font=f_lbl)
    draw.text((width - 60, y), "Date: 12-Nov-2024", fill="#64748B", font=f_val, anchor="rt")

    y += 35
    draw.text((60, y), "To,", fill="#0F172A", font=f_val)
    draw.text((60, y + 22), "Mr. Rohan Kolvekar", fill="#0F172A", font=f_lbl)
    draw.text((60, y + 44), "#42, 4th Cross, Indiranagar, Bengaluru, Karnataka - 560038", fill="#475569", font=f_val)
    draw.text((60, y + 66), "PAN: ABCDE1234F  |  Aadhaar: 4521 8832 9104", fill="#475569", font=f_val)

    y += 110
    draw.text((60, y), "Dear Sir,", fill="#0F172A", font=f_val)
    y += 25
    body = (
        "We are pleased to inform you that your application for an Education Loan under the Government of India "
        "PM-Vidyalaxmi Scheme has been officially sanctioned by the Competent Credit Authority. "
        "The terms and conditions of this financial facility are outlined below:"
    )
    draw.text((60, y), body[:100], fill="#334155", font=f_val)
    draw.text((60, y + 22), body[100:198], fill="#334155", font=f_val)
    draw.text((60, y + 44), body[198:], fill="#334155", font=f_val)

    y += 85
    # Table of Sanction Terms
    table_items = [
        ("Application Reference / CELAF ID", "CELAF-2024-PV88419", True),
        ("Sanctioned Loan Amount", "INR 7,50,000 (Rupees Seven Lakh Fifty Thousand Only)", True),
        ("Approved Degree / Course", "B.Tech Computer Science and Engineering", True),
        ("Educational Institution", "Indian Institute of Technology (IIT)", False),
        ("Effective Rate of Interest", "8.45% per annum (Floating Linked to EBLR)", False),
        ("Moratorium Facility", "Course Duration (4 Years) + 12 Months Grace Period", False),
        ("Repayment Tenure", "15 Years (180 Equated Monthly Installments)", False),
        ("DPDP Compliance Status", "Cryptographically Protected under DPDP Act 2023", False),
    ]

    for label, val, hl in table_items:
        draw.rectangle([60, y, width - 60, y + 36], fill="#F8FAFC" if not hl else "#EEF2FF", outline="#E2E8F0", width=1)
        draw.text((75, y + 8), label, fill="#475569", font=f_lbl)
        draw.text((450, y + 8), val, fill="#4338CA" if hl else "#0F172A", font=f_lbl if hl else f_val)
        y += 36

    y += 40
    draw.rounded_rectangle([60, y, width - 60, y + 80], radius=8, fill="#F0FDF4", outline="#BBF7D0", width=1)
    draw.text((75, y + 12), "DISBURSEMENT INSTRUCTIONS", fill="#166534", font=f_lbl)
    draw.text((75, y + 36), "The sanctioned amount of INR 7,50,000 will be remitted directly to the designated institution account.", fill="#15803D", font=f_sm)
    draw.text((75, y + 54), "All personal data is processed strictly per Section 6 Purpose Limitation guidelines.", fill="#15803D", font=f_sm)

    # Signatures
    y += 120
    draw.text((60, y), "Authorized Signatory", fill="#64748B", font=f_val)
    draw.text((60, y + 20), "Branch Credit Manager — SBI", fill="#0F172A", font=f_lbl)
    draw.text((width - 60, y), "Borrower Acceptance", fill="#64748B", font=f_val, anchor="rt")
    draw.text((width - 60, y + 20), "Rohan Kolvekar", fill="#0F172A", font=f_lbl, anchor="rt")

    out_path = OUTPUT_DIR / "loan_sanction_letter.png"
    img.save(out_path, format="PNG", dpi=(150, 150))
    print(f"Created: {out_path} ({width}x{height})")
    return out_path


def get_handwriting_font(size: int):
    """Loads a realistic cursive or handwriting font."""
    font_candidates = ["inkfree.ttf", "segoesc.ttf", "comic.ttf", "arial.ttf"]
    for fc in font_candidates:
        fp = Path("C:/Windows/Fonts") / fc
        if fp.exists():
            try:
                return ImageFont.truetype(str(fp), size)
            except Exception:
                continue
    return ImageFont.load_default()


def create_handwritten_application():
    """Generates a realistic handwritten leave application & medical report
    using natural handwriting fonts on a lined clinic sheet.
    """
    width = 950
    height = 1250
    # Warm ivory / notepad paper
    img = Image.new("RGB", (width, height), color="#FCFBF7")
    draw = ImageDraw.Draw(img)

    # Ruled faint notebook lines
    line_spacing = 38
    margin_top = 220
    for ly in range(margin_top, height - 80, line_spacing):
        draw.line([(50, ly), (width - 50, ly)], fill="#E5E7EB", width=1)

    # Red vertical margin line on left
    draw.line([(95, margin_top - 30), (95, height - 60)], fill="#FCA5A5", width=2)

    # Printed Clinic Header
    f_head = get_font(20, bold=True)
    f_sub = get_font(12, bold=False)
    f_sm = get_font(11, bold=False)

    draw.rectangle([0, 0, width, 140], fill="#F1F5F9")
    draw.line([(0, 140), (width, 140)], fill="#CBD5E1", width=2)

    draw.text((width // 2, 22), "CITY CARE CLINIC & DIAGNOSTIC CENTRE", fill="#0F172A", font=f_head, anchor="mt")
    draw.text((width // 2, 52), "#108, Healthcare Avenue, Malleshwaram, Bengaluru - 560003 | Ph: 080-23456789", fill="#475569", font=f_sub, anchor="mt")
    draw.text((width // 2, 74), "Dr. Rajesh Kulkarni, MBBS, MD (Internal Medicine) — Reg No: KMC-58291", fill="#1E40AF", font=f_sub, anchor="mt")
    draw.text((width // 2, 98), "PATIENT MEDICAL REPORT & STUDENT LEAVE RECOMMENDATION", fill="#DC2626", font=f_sub, anchor="mt")

    # Handwriting styling
    f_hw_lg = get_handwriting_font(23)
    f_hw_md = get_handwriting_font(20)
    f_hw_sm = get_handwriting_font(18)
    ink_color = "#1E3A8A"  # Royal blue ballpoint pen ink

    # Date and place
    draw.text((width - 80, 160), "Date: 14-Nov-2024", fill=ink_color, font=f_hw_sm, anchor="rt")
    draw.text((width - 80, 185), "Place: Bengaluru", fill=ink_color, font=f_hw_sm, anchor="rt")

    # Letter body
    y = 230
    draw.text((115, y), "To,", fill=ink_color, font=f_hw_md)
    y += line_spacing
    draw.text((115, y), "The Head of Department (HOD),", fill=ink_color, font=f_hw_md)
    y += line_spacing
    draw.text((115, y), "Department of Computer Science & Engineering,", fill=ink_color, font=f_hw_md)
    y += line_spacing
    draw.text((115, y), "National Institute of Technology (NIT).", fill=ink_color, font=f_hw_md)
    y += line_spacing + 5

    draw.text((115, y), "Subject: Medical Leave Application & Doctor Advice Report", fill=ink_color, font=f_hw_lg)
    y += line_spacing + 5

    draw.text((115, y), "Respected Sir / Madam,", fill=ink_color, font=f_hw_md)
    y += line_spacing

    draw.text((115, y), "I am writing to formally submit this leave application on medical grounds.", fill=ink_color, font=f_hw_md)
    y += line_spacing
    draw.text((115, y), "Patient Name: Sneha Patil", fill=ink_color, font=f_hw_lg)
    y += line_spacing
    draw.text((115, y), "Roll Number / Student ID: 21CS088", fill=ink_color, font=f_hw_lg)
    y += line_spacing
    draw.text((115, y), "Aadhaar Card Reference: 6712 3490 8125", fill=ink_color, font=f_hw_md)
    y += line_spacing
    draw.text((115, y), "Contact Mobile Number: +91 98451 22340", fill=ink_color, font=f_hw_md)
    y += line_spacing

    draw.text((115, y), "Medical Diagnosis: Acute Viral Jaundice with High Fever", fill=ink_color, font=f_hw_lg)
    y += line_spacing
    draw.text((115, y), "Consulting Physician: Dr. Rajesh Kulkarni (City Care Clinic)", fill=ink_color, font=f_hw_md)
    y += line_spacing
    draw.text((115, y), "Prescribed Period of Leave: 14 Days (Strict Bed Rest)", fill=ink_color, font=f_hw_lg)
    y += line_spacing
    draw.text((115, y), "Leave Dates Requested: 14-Nov-2024 to 28-Nov-2024", fill=ink_color, font=f_hw_md)
    y += line_spacing

    draw.text((115, y), "I kindly request you to approve my leave for 14 days and excuse", fill=ink_color, font=f_hw_md)
    y += line_spacing
    draw.text((115, y), "my absence from laboratory and theoretical lecture sessions.", fill=ink_color, font=f_hw_md)
    y += line_spacing + 15

    draw.text((115, y), "Thanking you,", fill=ink_color, font=f_hw_md)
    y += line_spacing
    draw.text((115, y), "Yours obediently,", fill=ink_color, font=f_hw_md)
    y += line_spacing
    draw.text((115, y), "Sneha Patil (Roll No: 21CS088)", fill=ink_color, font=f_hw_lg)

    # Doctor stamp & signature box on right
    stamp_y = y - 40
    draw.rounded_rectangle([width - 320, stamp_y, width - 60, stamp_y + 110], radius=8, outline="#1E40AF", width=2)
    draw.text((width - 190, stamp_y + 12), "CLINICAL ATTESTATION", fill="#1E40AF", font=f_sm, anchor="mt")
    draw.text((width - 190, stamp_y + 32), "City Care Clinic & Diagnostics", fill="#1E3A8A", font=f_sm, anchor="mt")
    draw.text((width - 190, stamp_y + 52), "Signed: Dr. Rajesh Kulkarni", fill="#1E3A8A", font=f_hw_sm, anchor="mt")
    draw.text((width - 190, stamp_y + 80), "Reg: KMC-58291 / Approved", fill="#059669", font=f_sm, anchor="mt")

    # DPDP privacy notice at bottom
    draw.text((width // 2, height - 30), "DPDP Act 2023 Compliant: Health and Medical Personal Identifiers Masked by PrivaGate Gateway", fill="#9CA3AF", font=f_sm, anchor="mt")

    out_path = OUTPUT_DIR / "handwritten_leave_application.png"
    img.save(out_path, format="PNG", dpi=(150, 150))
    print(f"Created: {out_path} ({width}x{height})")
    return out_path


def create_blossoms_therapy_form():
    """Generates a high-resolution, realistic patient intake & clinical therapy form
    for Blossom's Therapy Center.
    """
    width = 1000
    height = 1350
    img = Image.new("RGB", (width, height), color="#FFFFFF")
    draw = ImageDraw.Draw(img)

    f_title = get_font(24, bold=True)
    f_sub = get_font(13, bold=False)
    f_sec = get_font(15, bold=True)
    f_lbl = get_font(13, bold=True)
    f_val = get_font(13, bold=False)
    f_sm = get_font(11, bold=False)

    # Top Clinic Header Banner (Teal Theme)
    draw.rectangle([0, 0, width, 120], fill="#0F766E")
    draw.text((width // 2, 22), "BLOSSOM'S THERAPY CENTER", fill="#FFFFFF", font=f_title, anchor="mt")
    draw.text((width // 2, 56), "Comprehensive Pediatric Rehabilitation & Child Development Clinic", fill="#CCFBF1", font=f_sub, anchor="mt")
    draw.text((width // 2, 80), "#45, Rainbow Crescent, Koramangala 4th Block, Bengaluru - 560034 | Ph: +91 98765 11223", fill="#99F6E4", font=f_sm, anchor="mt")

    # Document Frame
    draw.rounded_rectangle([40, 140, width - 40, height - 50], radius=10, fill="#FFFFFF", outline="#CBD5E1", width=2)

    # Sub-Banner Form Title
    draw.text((width // 2, 160), "PATIENT INTAKE & CLINICAL THERAPY REGISTRATION FORM", fill="#0F172A", font=f_sec, anchor="mt")
    draw.line([(60, 190), (width - 60, 190)], fill="#E2E8F0", width=1)

    y = 205

    def draw_sec_header(title: str, curr_y: int) -> int:
        draw.rounded_rectangle([60, curr_y, width - 60, curr_y + 30], radius=5, fill="#F0FDFA", outline="#99F6E4", width=1)
        draw.text((75, curr_y + 6), title, fill="#0F766E", font=f_sec)
        return curr_y + 42

    def draw_field_row(fields: list, curr_y: int) -> int:
        col_w = (width - 120) // len(fields)
        for i, (label, val, highlight) in enumerate(fields):
            col_x = 60 + (i * col_w)
            draw.text((col_x + 10, curr_y), label, fill="#64748B", font=f_lbl)
            val_color = "#0F766E" if highlight else "#0F172A"
            draw.text((col_x + 10, curr_y + 20), val, fill=val_color, font=f_val)
        return curr_y + 48

    # Section 1: Patient Information
    y = draw_sec_header("1. PATIENT DEMOGRAPHICS & IDENTIFICATION", y)
    y = draw_field_row([
        ("Patient Full Name:", "Aarav Sharma", True),
        ("Date of Birth / Age:", "12-May-2018 (Age: 6 Years)", False),
        ("Gender:", "Male", False),
    ], y)
    y = draw_field_row([
        ("National ID / Aadhaar Reference:", "3892 4510 6721", True),
        ("Primary Language at Home:", "English, Hindi, Kannada", False),
        ("School Enrolled:", "Oakridge International School (Grade 1)", False),
    ], y)

    # Section 2: Parent / Guardian Information
    y = draw_sec_header("2. PARENT / PRIMARY GUARDIAN DETAILS", y)
    y = draw_field_row([
        ("Parent / Guardian Name:", "Vikram Sharma", True),
        ("Relationship to Patient:", "Father", False),
        ("Mother's Name:", "Priya Sharma", False),
    ], y)
    y = draw_field_row([
        ("Primary Contact Mobile:", "+91 98452 77889", True),
        ("Emergency Contact:", "+91 98451 33445", False),
        ("Guardian Email:", "vikram.sharma@example.com", False),
    ], y)
    y = draw_field_row([
        ("Permanent Residential Address:", "#12, Palm Grove, HSR Layout Sector 2, Bengaluru, Karnataka - 560102", False),
    ], y)

    # Section 3: Clinical Therapy Referral & Assessment
    y = draw_sec_header("3. CLINICAL REFERRAL & THERAPEUTIC ASSESSMENT", y)
    y = draw_field_row([
        ("Referring Pediatrician:", "Dr. Sunita Rao, MD (Pediatrics) — Rainbow Children Hospital", False),
        ("Intake Registration Date:", "14-Nov-2024", False),
    ], y)
    y = draw_field_row([
        ("Primary Therapy Program Requested:", "Pediatric Speech Therapy & Sensory Occupational Therapy", True),
    ], y)
    y = draw_field_row([
        ("Chief Complaints / Presenting Concerns:", "Expressive Language Delay, Articulation Challenges, & Sensory Tactile Sensitivity", False),
    ], y)
    y = draw_field_row([
        ("Clinical Diagnosis / Impression:", "Mild Expressive Speech Delay & Sensory Processing Sensitivity", True),
        ("Session Frequency:", "3 Sessions / Week", False),
    ], y)
    y = draw_field_row([
        ("Attending Senior Therapist:", "Dr. Meera Nambiar, OTR/L (Senior Clinical Specialist)", True),
        ("Clinic Center Branch:", "Blossom's Therapy Center — Koramangala Hub", False),
    ], y)

    # Section 4: Medical History & Milestones
    y = draw_sec_header("4. DEVELOPMENTAL HISTORY & MEDICAL PROFILE", y)
    y = draw_field_row([
        ("Birth History / Gestation:", "Full Term Normal Delivery (No NICU Stay)", False),
        ("Hearing & Vision Screening:", "Normal / Passed at 4 Years", False),
    ], y)
    y = draw_field_row([
        ("Known Allergies or Medications:", "No Known Drug Allergies (NKDA)", False),
        ("Prior Interventions:", "Attended 3 months early stimulation program", False),
    ], y)

    # Section 5: DPDP Consent & Confidentiality Assurance
    y = draw_sec_header("5. DIGITAL PERSONAL DATA PROTECTION (DPDP) CONSENT", y)
    draw.rounded_rectangle([60, y, width - 60, y + 80], radius=6, fill="#F0FDF4", outline="#BBF7D0", width=1)
    draw.text((75, y + 10), "🛡️ HEALTH & MEDICAL DATA CONFIDENTIALITY ATTESTATION (DPDP ACT 2023)", fill="#166534", font=f_lbl)
    draw.text((75, y + 32), "Parental consent is formally granted to Blossom's Therapy Center for clinical diagnostic evaluation and therapy.", fill="#15803D", font=f_sm)
    draw.text((75, y + 50), "All child health data and identity tokens are pseudonymized and protected via PrivaGate DPDP Gateway.", fill="#15803D", font=f_sm)

    # Signatures
    y += 110
    draw.text((80, y), "Parent / Guardian Signature", fill="#64748B", font=f_sm)
    draw.text((80, y + 18), "Vikram Sharma", fill="#0F172A", font=f_lbl)

    draw.text((width - 80, y), "Attending Clinical Therapist", fill="#64748B", font=f_sm, anchor="rt")
    draw.text((width - 80, y + 18), "Dr. Meera Nambiar, OTR/L", fill="#0F766E", font=f_lbl, anchor="rt")

    out_path = OUTPUT_DIR / "blossoms_therapy_center_patient_form.png"
    img.save(out_path, format="PNG", dpi=(150, 150))
    print(f"Created: {out_path} ({width}x{height})")
    return out_path


if __name__ == "__main__":
    create_celaf_document()
    create_aadhaar_card()
    create_loan_sanction_letter()
    create_handwritten_application()
    create_blossoms_therapy_form()
    print("All sample document images generated successfully!")

