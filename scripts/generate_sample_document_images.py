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

if __name__ == "__main__":
    create_celaf_document()
    create_aadhaar_card()
    create_loan_sanction_letter()
    print("All sample document images generated successfully!")
