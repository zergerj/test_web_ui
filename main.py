import base64
import hashlib
import hmac
import os

from fastapi import FastAPI, Request, HTTPException

app = FastAPI()

SHOPIFY_WEBHOOK_SECRET = os.getenv("SHOPIFY_WEBHOOK_SECRET", "")


@app.get("/")
def health():
    return {"status": "ok"}


@app.post("/webhooks/shopify")
async def shopify_webhook(request: Request):
    body = await request.body()

    topic = request.headers.get("X-Shopify-Topic")
    shop = request.headers.get("X-Shopify-Shop-Domain")
    received_hmac = request.headers.get("X-Shopify-Hmac-Sha256")

    print(f"Shopify webhook received")
    print(f"Topic: {topic}")
    print(f"Shop: {shop}")
    print(f"Body: {body.decode('utf-8')}")

    # Verify webhook if secret is configured
    if SHOPIFY_WEBHOOK_SECRET:
        calculated_hmac = base64.b64encode(
            hmac.new(
                SHOPIFY_WEBHOOK_SECRET.encode("utf-8"),
                body,
                hashlib.sha256,
            ).digest()
        ).decode("utf-8")

        if not received_hmac or not hmac.compare_digest(
            calculated_hmac,
            received_hmac,
        ):
            print("Invalid Shopify HMAC")
            raise HTTPException(status_code=401, detail="Invalid HMAC")

        print("Shopify HMAC verified")

    return {"received": True}
