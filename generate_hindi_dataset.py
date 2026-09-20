"""
generate_hindi_dataset.py
Builds phishing_dataset_hi.csv — a labeled Hindi / code-mixed Hinglish corpus
of phishing vs legitimate messages, for the second (regional-language) model.

WHY THIS EXISTS: the English model is trained on the Enron corpus plus a
modern synthetic supplement — all English. A large share of real fraud aimed
at Indian citizens and PSU staff arrives in Hindi or romanized Hinglish
("aapka KYC update karein", "khata band ho jayega"). Scored by an
English-only TF-IDF model those messages contain almost no known vocabulary,
so they land near the model's prior and slip through as Safe.

HONESTY NOTE, say this plainly if asked: this dataset is synthetic,
template-generated from real scam patterns (KYC/Aadhaar/UPI/bank-block/
lottery/electricity-disconnection SMS-and-email fraud widely reported in
India), not a scraped real-world Hindi phishing corpus — no public one of
comparable quality exists. It is a demonstrated capability and a working
pipeline, not a benchmarked detector. If you find a real corpus, this file
is the only thing that needs replacing; train_model_hi.py reads the same
text/label CSV either way.

Usage:
    python3 generate_hindi_dataset.py
"""

import csv
import random

random.seed(7)

PHISH_HI_SUBJECTS = [
    "तुरंत ध्यान दें: आपका खाता बंद किया जा रहा है",
    "KYC अपडेट करें वरना खाता ब्लॉक हो जाएगा",
    "आपके खाते में संदिग्ध लेनदेन पाया गया",
    "आधार लिंक करना अनिवार्य है - अंतिम सूचना",
    "बधाई हो! आपने लॉटरी जीती है",
    "बिजली कनेक्शन आज रात काट दिया जाएगा",
    "आपका डेबिट कार्ड ब्लॉक कर दिया गया है",
    "इनकम टैक्स रिफंड लंबित है",
]

PHISH_HI_BODIES = [
    "प्रिय ग्राहक, आपका बैंक खाता 24 घंटे में बंद कर दिया जाएगा। कृपया तुरंत "
    "इस लिंक पर क्लिक करके अपना KYC अपडेट करें और खाता विवरण सत्यापित करें: {url}",

    "आपके खाते में संदिग्ध गतिविधि देखी गई है। खाता सुरक्षित करने के लिए अभी "
    "अपना डेबिट कार्ड नंबर, CVV और OTP दर्ज करें: {url}",

    "आधार को बैंक खाते से लिंक करना अनिवार्य कर दिया गया है। आज ही लिंक करें "
    "अन्यथा आपकी सभी सेवाएं बंद हो जाएंगी। यहां क्लिक करें: {url}",

    "बधाई हो! आपका मोबाइल नंबर 25,00,000 रुपये की लकी ड्रॉ लॉटरी के लिए चुना "
    "गया है। इनाम पाने के लिए प्रोसेसिंग शुल्क जमा करें और बैंक विवरण भेजें: {url}",

    "आपका बिजली बिल बकाया है। आज रात 9:30 बजे कनेक्शन काट दिया जाएगा। तुरंत "
    "भुगतान करने के लिए इस लिंक पर जाएं: {url}",

    "इनकम टैक्स विभाग: आपका 15,490 रुपये का रिफंड लंबित है। खाता संख्या और "
    "IFSC कोड सत्यापित करें: {url}",
]

PHISH_HINGLISH_SUBJECTS = [
    "URGENT: aapka account band ho jayega",
    "KYC update karein turant - last warning",
    "Aapke khate me suspicious transaction",
    "Aadhaar link nahi hua to service band",
    "Congratulations! Aapne lottery jeeti hai",
    "Bijli connection aaj raat kat jayega",
]

PHISH_HINGLISH_BODIES = [
    "Dear customer, aapka bank khata 24 ghante me band ho jayega. Kripya turant "
    "is link par click karke KYC update karein aur account details verify karein: {url}",

    "Aapke account me suspicious activity detect hui hai. Account secure karne ke "
    "liye abhi debit card number, CVV aur OTP enter karein: {url}",

    "Aadhaar ko bank account se link karna zaroori hai. Aaj hi link karein warna "
    "sabhi services band ho jayengi. Yahan click karein: {url}",

    "Badhai ho! Aapka mobile number 25 lakh rupaye ki lucky draw lottery ke liye "
    "select hua hai. Prize claim karne ke liye processing fees bhejein: {url}",

    "Aapka electricity bill pending hai. Aaj raat 9:30 baje connection kat diya "
    "jayega. Turant payment karne ke liye is link par jayein: {url}",

    "UPI se aapke khate se paisa kat gaya hai. Refund pane ke liye neeche diye "
    "gaye link par apna UPI PIN daalein: {url}",
]

LEGIT_HI_SUBJECTS = [
    "कल की टीम मीटिंग का एजेंडा",
    "मासिक रिपोर्ट संलग्न है",
    "छुट्टी के आवेदन की स्वीकृति",
    "परियोजना की प्रगति पर चर्चा",
    "कार्यालय स्थानांतरण की सूचना",
    "प्रशिक्षण कार्यक्रम पंजीकरण",
]

LEGIT_HI_BODIES = [
    "नमस्ते, कल सुबह 11 बजे होने वाली टीम मीटिंग का एजेंडा संलग्न है। कृपया "
    "अपने विभाग की प्रगति रिपोर्ट साथ लेकर आएं। धन्यवाद।",

    "सभी को सूचित किया जाता है कि इस माह की समीक्षा बैठक शुक्रवार को सम्मेलन "
    "कक्ष में आयोजित की जाएगी। उपस्थिति अनिवार्य है।",

    "आपके अवकाश आवेदन को स्वीकृति दे दी गई है। कृपया अपने कार्य की जिम्मेदारी "
    "सौंपकर जाएं। शुभकामनाएं।",

    "परियोजना की प्रगति संतोषजनक है। अगले चरण की योजना पर चर्चा करने के लिए "
    "कृपया अपनी सुविधा का समय बताएं।",

    "प्रशिक्षण कार्यक्रम के लिए पंजीकरण खुला है। इच्छुक कर्मचारी मानव संसाधन "
    "विभाग से संपर्क करें।",
]

LEGIT_HINGLISH_BODIES = [
    "Namaste, kal 11 baje ki team meeting ka agenda attach kiya hai. Apni "
    "department report saath lekar aayein. Dhanyavaad.",

    "Sabhi ko suchit kiya jata hai ki is mahine ki review meeting Friday ko "
    "conference room me hogi. Attendance zaroori hai.",

    "Aapka leave application approve ho gaya hai. Jaane se pehle apna kaam "
    "handover kar dein. Shubhkamnayein.",

    "Project ki progress theek chal rahi hai. Agle phase ki planning ke liye "
    "apna convenient time bata dein.",

    "Training program ke liye registration khula hai. Interested employees HR "
    "department se contact karein.",
]

PHISH_URLS = [
    "http://sbi-kyc-update.online/verify",
    "http://secure-netbanking.in-verify.top/login",
    "http://aadhaar-link-portal.xyz/update",
    "http://bit.ly/kyc-update-now",
    "http://incometax-refund-gov.click/claim",
    "http://upi-refund-help.work/claim",
]

LEGIT_SENDERS = [
    "hr@nic.in", "admin@company.co.in", "principal@college.edu.in",
    "accounts@firm.in", "training@psu.gov.in",
]

PHISH_SENDERS = [
    "alert@sbi-secure-verify.online", "kyc@bank-update.top",
    "noreply@aadhaar-verify.xyz", "refund@incometax-gov.click",
    "support@upi-helpdesk.work",
]


def _sample(subject_pool, body_pool, sender_pool, label, with_url):
    subject = random.choice(subject_pool)
    body = random.choice(body_pool)
    if with_url:
        body = body.format(url=random.choice(PHISH_URLS))
    sender = random.choice(sender_pool)
    text = f"From: {sender}\nSubject: {subject}\n\n{body}"
    return [text, label]


def generate(n_per_class: int = 400, out_path: str = "phishing_dataset_hi.csv") -> str:
    rows = []
    for _ in range(n_per_class // 2):
        rows.append(_sample(PHISH_HI_SUBJECTS, PHISH_HI_BODIES, PHISH_SENDERS, 1, True))
        rows.append(_sample(PHISH_HINGLISH_SUBJECTS, PHISH_HINGLISH_BODIES, PHISH_SENDERS, 1, True))
        rows.append(_sample(LEGIT_HI_SUBJECTS, LEGIT_HI_BODIES, LEGIT_SENDERS, 0, False))
        rows.append(_sample(LEGIT_HI_SUBJECTS, LEGIT_HINGLISH_BODIES, LEGIT_SENDERS, 0, False))
    random.shuffle(rows)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["text", "label"])
        w.writerows(rows)
    print(f"Generated {len(rows)} Hindi/Hinglish samples -> {out_path}")
    return out_path


if __name__ == "__main__":
    generate()
