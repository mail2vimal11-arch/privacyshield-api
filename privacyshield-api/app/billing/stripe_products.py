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
    "personal":     "price_REPLACE_WITH_PERSONAL_PRICE_ID",      # $29/month
    "professional": "price_REPLACE_WITH_PROFESSIONAL_PRICE_ID",  # $99/month
    "business":     "price_REPLACE_WITH_BUSINESS_PRICE_ID",      # $999/month
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
