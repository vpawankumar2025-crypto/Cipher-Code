"""
generate_dataset.py
Builds a labeled synthetic dataset of phishing vs legitimate email text for
training a real ML classifier.

WHY SYNTHETIC: This sandbox environment cannot reach Kaggle/HuggingFace to
download the real "Phishing Email Dataset" / SpamAssassin corpus referenced
in the pitch deck (network restricted to package registries only).
This generator produces comparable structure/variety so the pipeline has a
REAL trained model today. On your own machine with full internet, swap this
for the actual Kaggle dataset (see README) for a stronger, more defensible model.
"""

import random
import csv

random.seed(42)

PHISHING_SUBJECTS = [
    "URGENT: Your account will be suspended",
    "Verify your account immediately",
    "Unusual activity detected on your account",
    "Your payment could not be processed",
    "Action required: confirm your identity",
    "Your account has been limited",
    "Security alert: unauthorized login attempt",
    "Final notice: account closure pending",
    "You have won a prize! Claim now",
    "Invoice attached - payment overdue",
    "Your package could not be delivered",
    "IT Department: password expiring today",
    "Confirm your recent transaction",
    "Your subscription has expired - renew now",
    "Tax refund pending - claim your refund",
]

PHISHING_BODIES = [
    "Dear Customer, we have detected unusual activity on your account. "
    "Your account will be suspended within 24 hours unless you verify your "
    "identity immediately. Click here to confirm your password and account "
    "details: {url}",

    "URGENT ACTION REQUIRED. Your account has been flagged for suspicious "
    "activity. Failure to verify within 24 hours will result in permanent "
    "suspension. Please confirm your bank details and login credentials here: {url}",

    "We were unable to process your recent payment. To avoid service "
    "interruption, please update your billing information and confirm your "
    "card details at the following link: {url}",

    "Congratulations! You have been selected to receive a gift card worth "
    "$500. Click here now to claim your prize before it expires: {url}",

    "This is a final notice regarding your account. Immediate verification "
    "is required to prevent permanent closure. Act now and confirm your "
    "one time password (OTP) here: {url}",

    "Your package delivery failed due to an incomplete address. Please "
    "confirm your details and pay a small redelivery fee here: {url}",

    "IT Support: Your password will expire today. To avoid being locked "
    "out, please verify your credentials immediately using this secure link: {url}",

    "We detected a login attempt from a new device. If this wasn't you, "
    "click here immediately to secure your account and reset your password: {url}",
]

PHISHING_SENDERS = [
    '"PayPal Security" <security@paypa1-alerts.com>',
    '"Bank Support" <support@secure-bank-verify.com>',
    '"Amazon Delivery" <delivery@amaz0n-shipping.net>',
    '"IT Helpdesk" <helpdesk@company-mail-secure.com>',
    '"Netflix Billing" <billing@netfliix-account.com>',
    '"Microsoft Account Team" <account@microsofft-security.com>',
    '"Apple Support" <support@apple-id-verify.net>',
    '"Tax Refund Dept" <refunds@govt-tax-refund.com>',
]

SHORTENERS = ["bit.ly/verify123", "tinyurl.com/secure-login", "t.co/abc123", "goo.gl/xyz789"]

LEGIT_SUBJECTS = [
    "Your weekly account summary",
    "Meeting notes from today's call",
    "Project update - Q3 deliverables",
    "Your order has been shipped",
    "Reminder: team standup tomorrow at 10am",
    "Invoice for your records",
    "Newsletter: this month's highlights",
    "Thank you for your purchase",
    "Your flight itinerary",
    "Welcome to our platform",
    "Monthly statement is now available",
    "Re: question about the report",
    "Follow up on our conversation",
    "Your subscription receipt",
    "Event invitation: annual conference",
]

LEGIT_BODIES = [
    "Hi, here is a quick summary of what we covered in today's meeting. "
    "Let me know if you have any questions or would like to discuss further.",

    "Thank you for your recent purchase. Your order has been shipped and "
    "should arrive within 3-5 business days. You can track your package "
    "using the link in your account dashboard.",

    "Hi team, just a reminder that our standup is scheduled for tomorrow "
    "at 10am. Please come prepared with updates on your current tasks.",

    "Please find attached the invoice for last month's services. Let us "
    "know if you have any questions regarding the billing details.",

    "Welcome aboard! We're excited to have you join our platform. Feel "
    "free to explore the dashboard and reach out if you need any help "
    "getting started.",

    "Here is this month's newsletter with highlights from our team, "
    "product updates, and upcoming events. Thanks for being a valued member.",

    "Your monthly statement is now available in your account. You can "
    "view and download it anytime from the billing section.",

    "Following up on our earlier conversation - let me know if you'd like "
    "to schedule a call this week to go over the details further.",
]

LEGIT_SENDERS = [
    '"Google Notifications" <notifications@google.com>',
    '"Amazon" <orders@amazon.com>',
    '"Slack" <notifications@slack.com>',
    '"GitHub" <notifications@github.com>',
    '"LinkedIn" <messages@linkedin.com>',
    '"Zoom" <no-reply@zoom.us>',
    '"Netflix" <info@netflix.com>',
    '"Your Company HR" <hr@yourcompany.com>',
]


def make_phishing_sample():
    subject = random.choice(PHISHING_SUBJECTS)
    body = random.choice(PHISHING_BODIES).format(url=f"http://{random.choice(SHORTENERS)}")
    sender = random.choice(PHISHING_SENDERS)
    text = f"From: {sender}\nSubject: {subject}\n\n{body}"
    return text, 1


def make_legit_sample():
    subject = random.choice(LEGIT_SUBJECTS)
    body = random.choice(LEGIT_BODIES)
    sender = random.choice(LEGIT_SENDERS)
    text = f"From: {sender}\nSubject: {subject}\n\n{body}"
    return text, 0


def generate_dataset(n_per_class=400, out_path="phishing_dataset.csv"):
    rows = []
    for _ in range(n_per_class):
        rows.append(make_phishing_sample())
        rows.append(make_legit_sample())
    random.shuffle(rows)

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        writer.writerows(rows)

    print(f"Generated {len(rows)} samples -> {out_path}")
    return out_path


if __name__ == "__main__":
    generate_dataset()
