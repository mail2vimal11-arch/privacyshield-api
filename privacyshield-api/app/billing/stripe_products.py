"""
stripe_products.py — Stripe Product & Price ID mapping
After creating products in your Stripe dashboard, paste the Price IDs here.
"""

# ----------------------------------------------------------------
# INSTRUCTIONS:
# 1. Go to https://dashboard.stripe.com/products
# 2. Create a product for each plan
# 3. Add a "Recurring" price to each product (monthly)
# 4. Copy the Price ID (starts with "price_") and paste below
# ----------------------------------------------------------------

STRIPE_PRICE_IDS = {
    "personal":     "price_1TIjBKPK9MwlrJaJSOexfeCz",      # $29/month
    "professional": "price_1TIjBFPK9MwlrJaJYMwiy7IY",  # $99/month
    "business":     "price_1TIjBGPK9MwlrJaJZLM1F6g2",      # $999/month
}

PLAN_MONTHLY_QUOTAS = {
    "personal":     50,
    "professional": 500,
    "business":     5000,
    "enterprise":   99999,
}

PLAN_NAMES = {
    "personal":     "Personal ($29/month)",
    "professional": "Professional ($99/month)",
    "business":     "Business ($999/month)",
}
