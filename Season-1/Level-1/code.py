from dataclasses import dataclass
from decimal import Decimal
from typing import List

MAX_ITEM_AMOUNT = 100000  # maximum price of item in the shop
MAX_QUANTITY = 100        # maximum quantity of an item in the shop
MIN_QUANTITY = 0          # minimum quantity of an item in the shop
MAX_TOTAL = Decimal('1e6')  # maximum total amount accepted for an order


@dataclass
class Item:
    type: str
    description: str
    amount: float
    quantity: int


@dataclass
class Order:
    id: str
    items: List[Item]


def is_valid_payment_amount(amount):
    return -MAX_ITEM_AMOUNT <= amount <= MAX_ITEM_AMOUNT


def is_valid_product(item):
    return (
        isinstance(item.quantity, int)
        and MIN_QUANTITY < item.quantity <= MAX_QUANTITY
        and MIN_QUANTITY < item.amount <= MAX_ITEM_AMOUNT
    )


def validorder(order):
    payments = Decimal('0')
    expenses = Decimal('0')

    for item in order.items:
        if item.type == 'payment':
            if is_valid_payment_amount(item.amount):
                payments += Decimal(str(item.amount))

        elif item.type == 'product':
            if is_valid_product(item):
                expenses += Decimal(str(item.amount)) * item.quantity

        else:
            return f"Invalid item type: {item.type}"

    if abs(payments) > MAX_TOTAL or expenses > MAX_TOTAL:
        return "Total amount payable for an order exceeded"

    if payments != expenses:
        return f"Order ID: {order.id} - Payment imbalance: ${payments - expenses:0.2f}"

    return f"Order ID: {order.id} - Full payment received!"