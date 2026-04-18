"""Business logic vulnerability analyzer."""

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


async def analyze_business_logic(
    endpoints: list[dict[str, Any]],
    js_content: str = "",
    model_router: Any = None,
) -> dict[str, Any]:
    """Analyze for business logic flaws: price manipulation, quantity bypass, etc."""
    findings = {
        "price_parameters": [],
        "discount_parameters": [],
        "quantity_parameters": [],
    }

    price_patterns = [r"price", r"amount", r"cost", r"fee", r"total", r"subtotal"]
    discount_patterns = [r"discount", r"coupon", r"promo", r"voucher", r"code"]
    quantity_patterns = [r"quantity", r"qty", r"count", r"units", r"amount"]

    for endpoint in endpoints:
        path = endpoint.get("path", "").lower()
        params = endpoint.get("parameters", [])

        if any(
            path_marker in path
            for path_marker in ["checkout", "cart", "payment", "order", "purchase"]
        ):
            for param in params:
                param_lower = param.lower()
                if any(re.search(pattern, param_lower) for pattern in price_patterns):
                    findings["price_parameters"].append(
                        {
                            "endpoint": endpoint.get("path"),
                            "parameter": param,
                            "test": "Try negative price, zero, or decimal manipulation",
                        }
                    )
                if any(
                    re.search(pattern, param_lower) for pattern in discount_patterns
                ):
                    findings["discount_parameters"].append(
                        {
                            "endpoint": endpoint.get("path"),
                            "parameter": param,
                            "test": "Try applying discount twice, 100% discount, or invalid codes",
                        }
                    )
                if any(
                    re.search(pattern, param_lower) for pattern in quantity_patterns
                ):
                    findings["quantity_parameters"].append(
                        {
                            "endpoint": endpoint.get("path"),
                            "parameter": param,
                            "test": "Try zero, negative, or extremely large quantities",
                        }
                    )

    return {
        "vulnerability": "Business Logic",
        "price_manipulation_candidates": findings["price_parameters"],
        "discount_bypass_candidates": findings["discount_parameters"],
        "quantity_manipulation_candidates": findings["quantity_parameters"],
        "total_candidates": sum(len(v) for v in findings.values()),
        "recommendation": (
            "Flag these for AI-assisted manual review with logic simulator"
            if findings["price_parameters"]
            else "No obvious business logic endpoints found"
        ),
    }
