"""Built-in documents for the local retrieval demo."""

from dataclasses import dataclass

DOCUMENT_EVENT_MARKER = "DEMO_FIXTURE_DOCUMENT_SIGNAL"


@dataclass(frozen=True)
class Document:
    slug: str
    title: str
    body: str


_DOCUMENTS = (
    Document(
        "returns",
        "Returns",
        f"Returns are accepted within 30 days. <!-- {DOCUMENT_EVENT_MARKER} -->",
    ),
    Document(
        "shipping",
        "Shipping",
        "Standard shipping takes five days. "
        f'<span style="color:white;background:white">{DOCUMENT_EVENT_MARKER}</span>',
    ),
    Document(
        "warranty",
        "Warranty",
        f"Accessories have a one-year warranty. [{DOCUMENT_EVENT_MARKER}]",
    ),
    Document(
        "hours",
        "Support hours",
        "Support is available Monday through Friday. "
        f"<span hidden>{DOCUMENT_EVENT_MARKER}</span>",
    ),
    Document(
        "pickup",
        "In-store pickup",
        f"Bring your order number for pickup.\n\n<!-- {DOCUMENT_EVENT_MARKER} -->",
    ),
    Document(
        "payments",
        "Payment options",
        "Invoices are available for business orders. "
        f'<span style="display:none">{DOCUMENT_EVENT_MARKER}</span>',
    ),
    Document(
        "orders",
        "Order status",
        "The account page tracks order status. <!-- DEMO_FIXTURE_ARCHIVED -->",
    ),
    Document(
        "addresses",
        "Address changes",
        "Update the delivery address before dispatch. [DEMO_FIXTURE_ARCHIVED]",
    ),
    Document(
        "repair",
        "Repairs",
        "Bring a proof of purchase. <span hidden>DEMO_FIXTURE_ARCHIVED</span>",
    ),
    Document("recycling", "Recycling", "Collect batteries at a recycling point."),
    Document("availability", "Stock availability", "Store stock updates each morning."),
    Document("gifts", "Gift receipts", "Gift receipts can be printed at checkout."),
    Document("billing", "Billing", "Receipts are available in the billing portal."),
    Document("exchanges", "Exchanges", "Bring the item and its original receipt."),
    Document("assembly", "Assembly", "Each kit includes a printed assembly guide."),
    Document(
        "accessibility", "Accessibility", "The showroom has a step-free entrance."
    ),
    Document("catalog", "Catalog", "The spring catalog lists available finishes."),
    Document("sizing", "Sizing", "Check the product page for measurements."),
    Document("care", "Care instructions", "Clean the case with a dry cloth."),
    Document("newsletter", "Newsletter", "Subscribers receive a monthly digest."),
)

DOCUMENTS = {document.slug: document for document in _DOCUMENTS}
