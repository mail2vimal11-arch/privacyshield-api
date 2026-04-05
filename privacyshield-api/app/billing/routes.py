"""
routes.py — Stripe Billing
Handles subscription checkout, webhooks, and plan management.

Flow:
  1. Customer calls POST /v1/billing/checkout  → get a Stripe payment URL
  2. Customer pays on Stripe's hosted page
  3. Stripe calls POST /v1/billing/webhook     → we upgrade their plan in Supabase
  4. Customer is now on paid plan

Endpoints:
  POST /v1/billing/checkout          — Create Stripe checkout session
  POST /v1/billing/webhook           — Stripe webhook receiver (no auth)
  GET  /v1/billing/subscription      — Get current subscription status
  POST /v1/billing/cancel            — Cancel subscription
  GET  /v1/billing/portal            — Stripe customer portal (manage billing)
"""
import stripe
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

from app.core.auth import verify_api_key
from app.core.database import supabase
from app.core.config import settings
from app.billing.stripe_products import STRIPE_PRICE_IDS, PLAN_MONTHLY_QUOTAS

router = APIRouter(prefix="/billing", tags=["Billing"])


def get_stripe():
    if not settings.stripe_secret_key:
        raise HTTPException(
            status_code=503,
            detail="Stripe not configured. Add STRIPE_SECRET_KEY to environment variables."
        )
    stripe.api_key = settings.stripe_secret_key
    return stripe


# ----------------------------------------------------------------
# Request Models
# ----------------------------------------------------------------

class CheckoutRequest(BaseModel):
    plan: str                           # "personal" | "professional" | "business"
    success_url: Optional[str] = None   # Where to redirect after payment
    cancel_url: Optional[str] = None    # Where to redirect if cancelled


# ----------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------

@router.post("/checkout")
async def create_checkout_session(
    request: CheckoutRequest,
    customer: dict = Depends(verify_api_key)
):
    """
    Create a Stripe checkout session for upgrading to a paid plan.
    Returns a URL — redirect the user to it to complete payment.
    """
    s = get_stripe()

    if request.plan not in STRIPE_PRICE_IDS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan '{request.plan}'. Choose from: {list(STRIPE_PRICE_IDS.keys())}"
        )

    price_id = STRIPE_PRICE_IDS[request.plan]

    if "REPLACE_WITH" in price_id:
        raise HTTPException(
            status_code=503,
            detail=(
                f"Stripe Price ID for '{request.plan}' not configured. "
                "Go to stripe.com/products, create a product, and paste the Price ID into "
                "app/billing/stripe_products.py"
            )
        )

    app_url = settings.app_url
    success_url = request.success_url or f"{app_url}/billing/success?plan={request.plan}"
    cancel_url = request.cancel_url or f"{app_url}/billing"

    try:
        # Get or create Stripe customer
        stripe_customer_id = customer.get("stripe_customer_id")

        if not stripe_customer_id:
            stripe_customer = s.Customer.create(
                email=customer["email"],
                name=customer.get("full_name", ""),
                metadata={"privacyshield_customer_id": customer["id"]}
            )
            stripe_customer_id = stripe_customer.id

            # Save Stripe customer ID
            supabase.table("customers").update(
                {"stripe_customer_id": stripe_customer_id}
            ).eq("id", customer["id"]).execute()

        # Create checkout session
        session = s.checkout.Session.create(
            customer=stripe_customer_id,
            payment_method_types=["card"],
            line_items=[{
                "price": price_id,
                "quantity": 1
            }],
            mode="subscription",
            success_url=success_url + "&session_id={CHECKOUT_SESSION_ID}",
            cancel_url=cancel_url,
            metadata={
                "privacyshield_customer_id": customer["id"],
                "plan": request.plan
            },
            subscription_data={
                "metadata": {
                    "privacyshield_customer_id": customer["id"],
                    "plan": request.plan
                }
            }
        )

        return {
            "checkout_url": session.url,
            "session_id": session.id,
            "plan": request.plan,
            "expires_at": datetime.fromtimestamp(session.expires_at).isoformat() + "Z"
        }

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """
    Receives Stripe webhook events.
    This endpoint must be added to your Stripe webhook settings.
    URL: https://your-railway-url.railway.app/v1/billing/webhook
    Events to enable: customer.subscription.created, updated, deleted + invoice.payment_failed
    """
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="Stripe webhook secret not configured")

    # Verify the webhook signature (prevents fake webhooks)
    try:
        stripe.api_key = settings.stripe_secret_key
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.stripe_webhook_secret
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event["type"]
    data = event["data"]["object"]

    print(f"[webhook] Received: {event_type}")

    # ---- Subscription created or updated ----
    if event_type in ("customer.subscription.created", "customer.subscription.updated"):
        await _handle_subscription_update(data)

    # ---- Subscription cancelled ----
    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_cancelled(data)

    # ---- Payment failed ----
    elif event_type == "invoice.payment_failed":
        await _handle_payment_failed(data)

    # ---- Checkout completed (alternative trigger) ----
    elif event_type == "checkout.session.completed":
        await _handle_checkout_completed(data)

    return {"received": True}


@router.get("/subscription")
async def get_subscription(customer: dict = Depends(verify_api_key)):
    """Get current subscription status."""
    stripe_customer_id = customer.get("stripe_customer_id")

    if not stripe_customer_id:
        return {
            "plan": customer["plan"],
            "plan_status": customer["plan_status"],
            "stripe_connected": False,
            "message": "No payment method on file. Use POST /v1/billing/checkout to upgrade."
        }

    try:
        stripe.api_key = settings.stripe_secret_key
        subscriptions = stripe.Subscription.list(
            customer=stripe_customer_id,
            status="active",
            limit=1
        )

        if subscriptions.data:
            sub = subscriptions.data[0]
            return {
                "plan": customer["plan"],
                "plan_status": customer["plan_status"],
                "stripe_connected": True,
                "subscription_id": sub.id,
                "current_period_end": datetime.fromtimestamp(sub.current_period_end).isoformat() + "Z",
                "cancel_at_period_end": sub.cancel_at_period_end,
                "monthly_scan_quota": customer["monthly_scan_quota"],
                "monthly_scans_used": customer["monthly_scans_used"]
            }

    except stripe.error.StripeError as e:
        print(f"[billing] Stripe error: {e}")

    return {
        "plan": customer["plan"],
        "plan_status": customer["plan_status"],
        "stripe_connected": bool(stripe_customer_id)
    }


@router.post("/cancel")
async def cancel_subscription(customer: dict = Depends(verify_api_key)):
    """
    Cancel subscription at the end of the current billing period.
    Customer retains access until period ends.
    """
    stripe_customer_id = customer.get("stripe_customer_id")
    if not stripe_customer_id:
        raise HTTPException(status_code=400, detail="No active subscription found")

    try:
        stripe.api_key = settings.stripe_secret_key
        subscriptions = stripe.Subscription.list(
            customer=stripe_customer_id,
            status="active",
            limit=1
        )

        if not subscriptions.data:
            raise HTTPException(status_code=400, detail="No active subscription found")

        sub = stripe.Subscription.modify(
            subscriptions.data[0].id,
            cancel_at_period_end=True
        )

        supabase.table("customers").update(
            {"plan_status": "cancelling"}
        ).eq("id", customer["id"]).execute()

        return {
            "message": "Subscription will be cancelled at end of billing period",
            "access_until": datetime.fromtimestamp(sub.current_period_end).isoformat() + "Z",
            "subscription_id": sub.id
        }

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")


@router.get("/portal")
async def billing_portal(customer: dict = Depends(verify_api_key)):
    """
    Get a Stripe Customer Portal URL so the customer can manage their own billing,
    update card, download invoices, etc.
    """
    stripe_customer_id = customer.get("stripe_customer_id")
    if not stripe_customer_id:
        raise HTTPException(status_code=400, detail="No Stripe account linked to this customer")

    try:
        stripe.api_key = settings.stripe_secret_key
        session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url=f"{settings.app_url}/billing"
        )
        return {"portal_url": session.url}

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=f"Stripe error: {str(e)}")


# ----------------------------------------------------------------
# Internal webhook handlers
# ----------------------------------------------------------------

async def _handle_subscription_update(subscription: dict):
    """Upgrade or change customer plan when subscription is created/updated."""
    customer_id = (
        subscription.get("metadata", {}).get("privacyshield_customer_id")
    )

    if not customer_id:
        # Try to find by stripe_customer_id
        stripe_customer_id = subscription.get("customer")
        result = supabase.table("customers").select("id, plan").eq(
            "stripe_customer_id", stripe_customer_id
        ).execute()
        if result.data:
            customer_id = result.data[0]["id"]

    if not customer_id:
        print(f"[webhook] Could not find customer for subscription {subscription.get('id')}")
        return

    plan = subscription.get("metadata", {}).get("plan", "personal")
    status = subscription.get("status", "active")

    quota = PLAN_MONTHLY_QUOTAS.get(plan, 50)

    supabase.table("customers").update({
        "plan": plan,
        "plan_status": "active" if status == "active" else status,
        "monthly_scan_quota": quota
    }).eq("id", customer_id).execute()

    print(f"[webhook] Upgraded customer {customer_id} to {plan}")


async def _handle_subscription_cancelled(subscription: dict):
    """Downgrade customer to free plan when subscription ends."""
    stripe_customer_id = subscription.get("customer")

    result = supabase.table("customers").select("id").eq(
        "stripe_customer_id", stripe_customer_id
    ).execute()

    if result.data:
        customer_id = result.data[0]["id"]
        supabase.table("customers").update({
            "plan": "free",
            "plan_status": "cancelled",
            "monthly_scan_quota": 3
        }).eq("id", customer_id).execute()
        print(f"[webhook] Downgraded customer {customer_id} to free (subscription cancelled)")


async def _handle_payment_failed(invoice: dict):
    """Mark plan as past_due when payment fails."""
    stripe_customer_id = invoice.get("customer")

    result = supabase.table("customers").select("id").eq(
        "stripe_customer_id", stripe_customer_id
    ).execute()

    if result.data:
        customer_id = result.data[0]["id"]
        supabase.table("customers").update(
            {"plan_status": "past_due"}
        ).eq("id", customer_id).execute()
        print(f"[webhook] Marked customer {customer_id} as past_due")


async def _handle_checkout_completed(session: dict):
    """Handle completed checkout session."""
    customer_id = session.get("metadata", {}).get("privacyshield_customer_id")
    plan = session.get("metadata", {}).get("plan", "personal")

    if customer_id and plan:
        quota = PLAN_MONTHLY_QUOTAS.get(plan, 50)
        supabase.table("customers").update({
            "plan": plan,
            "plan_status": "active",
            "monthly_scan_quota": quota
        }).eq("id", customer_id).execute()
        print(f"[webhook] Checkout complete — customer {customer_id} now on {plan}")
