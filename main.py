#!/usr/bin/env python3

import argparse
import csv
import json
import os
from datetime import datetime, date, timezone
from dataclasses import dataclass, field
from typing import Optional, List
from urllib.parse import urljoin
import calendar

import requests
from web3 import Web3
from eth_account.messages import encode_defunct

URI = "https://gnosispay.com"
DOMAIN = "gnosispay.com"
CHAIN_ID = 100
DEFAULT_BASE_URL = "https://api.gnosispay.com"
APP_URI = "https://gnosispay.com"
API_BASE = "https://api.gnosispay.com"

# Gnosis transaction type codes
GNOSIS_CODES = {
    "00": "Purchase (POS)",
    "01": "Withdrawal (ATM)",
    "10": "Account Funding",
    "20": "Return of Goods",
    "28": "Prepaid Load",
    "30": "Balance Inquiry",
    "70": "PIN Change",
    "72": "PIN Unblock",
}

# ======== DATACLASSES =========

@dataclass
class Message:
    """
    SIWE Message
    """
    domain: str
    address: str  # Ethereum address as string
    uri: str      # URL as string
    version: str
    statement: Optional[str] = None
    nonce: str = ""
    chain_id: int = 1
    issued_at: str = ""
    expiration_time: Optional[str] = None
    not_before: Optional[str] = None
    request_id: Optional[str] = None
    resources: List[str] = field(default_factory=list)  # URLs as strings

@dataclass
class UserAPIResponse:
    email: str
    kyc_status: Optional[str] = None
    safe_wallets: List[str] = None
    
    def __post_init__(self):
        if self.safe_wallets is None:
            self.safe_wallets = []

@dataclass
class UserReferralsAPIResponse:
    is_og_token_holder: bool
    pending_referrals: int
    completed_refferals: int

@dataclass
class UserRewardsAPIResponse:
    is_og: bool = False
    gno_balance: Optional[str] = None
    cashback_rate: float = 0.0

@dataclass
class IBANDetailsAPIResponse:
    iban: Optional[str] = None
    bic: Optional[str] = None
    status: Optional[str] = None

@dataclass
class UserProfileAPIResponse:
    id: str
    email: str
    phone: str
    first_name: str
    last_name: str
    # address1 + " " + address2 + " " + city + " " + postalCode + " " + state + " " + country
    address: str  
    nationality: str
    sign_in_wallets: List[str]
    safe_wallets: List[str]
    kyc_status: str
    
    def __post_init__(self):
        if self.sign_in_wallets is None:
            self.sign_in_wallets = []
        if self.safe_wallets is None:
            self.safe_wallets = []

@dataclass
class TransactionAPIResponse:
    created_at: str
    is_pending: bool
    amount: float
    currency: str
    transaction_type: int
    mcc_code: int
    mcc_description: str
    merchant_name: str
    merchant_city: str
    merchant_country: str
    hash_id: str
    kind: str
    status: str

    @classmethod
    def from_json(cls, mcc_codes: dict, json_data: dict) -> 'TransactionAPIResponse':
        """
        Initialize a Transaction from JSON data.
        
        Args:
            mcc_codes: Dictionary of MCC codes and descriptions
            json_data: Dictionary containing transaction data
            
        Returns:
            Transaction: New Transaction instance
        """
        created_at = json_data["createdAt"]
        is_pending = json_data["isPending"]
        currency = json_data["transactionCurrency"]["symbol"]
        _decimals = json_data["transactionCurrency"]["decimals"]
        # We need to convert the amount to a float based on the decimals
        # e.g., 1920 and 2 decimals is 19.20
        amount = int(json_data["transactionAmount"]) / 10 ** _decimals
        transaction_type = json_data["transactionType"]
        mcc_code = json_data["mcc"]
        mcc_description = mcc_codes.get(str(mcc_code), f"Unknown MCC {mcc_code}")
        merchant_name = json_data["merchant"]["name"].strip()
        merchant_city = json_data["merchant"]["city"].strip()
        merchant_country = json_data["merchant"]["country"]["name"]
        hash_id = json_data["transactions"][-1]["hash"] if len(json_data["transactions"]) > 0 else ""
        kind = json_data["kind"]
        # In case of reversal, the status is not present
        status = json_data.get("status", "")
        
        return cls(
            created_at=created_at,
            is_pending=is_pending,
            amount=amount,
            currency=currency,
            transaction_type=transaction_type,
            mcc_code=mcc_code,
            mcc_description=mcc_description,
            merchant_name=merchant_name,
            merchant_city=merchant_city,
            merchant_country=merchant_country,
            hash_id=hash_id,
            kind=kind,
            status=status
        )

    @classmethod
    def to_csv_header(cls) -> List[str]:
        return [
            "created_at",
            "is_pending",
            "amount",
            "currency",
            "transaction_type",
            "mcc_code",
            "mcc_description",
            "merchant_name",
            "merchant_city",
            "merchant_country",
            "kind",
            "status"
        ]

    def print_transaction(self) -> None:
        print(f'Transaction('
              f'created_at="{get_date_only(self.created_at)}", '
              f'is_pending={self.is_pending}, '
              f'amount={self.amount}, '
              f'currency="{self.currency}", '
              f'transaction_type="{GNOSIS_CODES[str(self.transaction_type)]}", '
              f'mcc_code={self.mcc_code}, '
              f'mcc_description="{self.mcc_description}", '
              f'merchant_name="{self.merchant_name}", '
              f'merchant_city="{self.merchant_city}", '
              f'merchant_country="{self.merchant_country}", '
              f'kind="{self.kind}", '
              f'status="{self.status}")')

    def to_csv_row(self) -> List[str]:
        def escape_csv_value(value):
            str_value = str(value)
            if ',' in str_value or '"' in str_value or '\n' in str_value:
                return f'"{str_value.replace('"', '""')}"'
            return str_value
        return [
            escape_csv_value(get_date_only(self.created_at)),
            escape_csv_value(self.is_pending),
            escape_csv_value(self.amount),
            escape_csv_value(self.currency),
            escape_csv_value(GNOSIS_CODES[str(self.transaction_type)]),
            escape_csv_value(self.mcc_code),
            escape_csv_value(self.mcc_description),
            escape_csv_value(self.merchant_name),
            escape_csv_value(self.merchant_city),
            escape_csv_value(self.merchant_country),
            escape_csv_value(self.kind),
            escape_csv_value(self.status)
        ]

# ======== UTILITY FUNCTIONS =========

def get_date_only(date_str: str) -> str:
    return date_str.split('T')[0]

def read_mcc_json() -> dict:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    mcc_file = os.path.join(current_dir, "data", "mcc_codes.json")
    
    with open(mcc_file, 'r') as f:
        return {
            item["mcc"]: item["edited_description"].replace("( Not Elsewhere Classified)", "").strip()
            for item in json.load(f)
        }

# ======== AUTHENTICATION FUNCTIONS =========

def new_request(base_url, method, url_str, body=None, auth_token=None, user_agent="python-gnosispay"):
    """
    Prepare a request object.

    Args:
        base_url: Base URL for the API
        method: HTTP method (GET, POST, etc.)
        url_str: URL path relative to base_url
        body: Request body (will be JSON encoded)
        auth_token: Authentication token for Authorization header
        user_agent: User agent string
    
    Returns:
        requests.Request: Prepared request object
    """
    if url_str.startswith('http'):
        full_url = url_str
    else:
        full_url = urljoin(base_url, url_str)
    
    if body is not None:
        json_body = json.dumps(body)
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": user_agent
        }
    else:
        json_body = None
        headers = {
            "Accept": "application/json",
            "User-Agent": user_agent
        }
    
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    
    req = requests.Request(
        method=method,
        url=full_url,
        data=json_body,
        headers=headers
    )
    
    return req

def get_nonce(base_url, auth_token=None, user_agent="python-gnosispay"):
    """
    Get a nonce from the API.
    
    Args:
        base_url: Base URL for the API
        auth_token: Authentication token (optional)
        user_agent: User agent string
    
    Returns:
        str: The nonce string
    """
    req = new_request(
        base_url=base_url,
        method="GET",
        url_str="/api/v1/auth/nonce",
        body=None,
        auth_token=auth_token,
        user_agent=user_agent
    )
    
    with requests.Session() as session:
        resp = session.send(req.prepare())
        resp.raise_for_status()  # Raise exception for bad status codes
        return resp.text.strip()

def get_siwe_message(domain: str, address: str, uri: str, chain_id: int, base_url: str, auth_token: str = None, user_agent: str = "python-gnosispay") -> str:
    """
    Get a SIWE message.
    
    Args:
        domain: The domain for the SIWE message
        address: Ethereum address as string
        uri: The URI for the SIWE message
        chain_id: The chain ID
        base_url: Base URL for API requests
        auth_token: Authentication token (optional)
        user_agent: User agent string
    
    Returns:
        str: The SIWE message string
    """
    nonce = get_nonce(base_url, auth_token, user_agent)
    
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    message = (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        "Sign in with Ethereum\n\n"
        f"URI: {uri}\n"
        "Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {now}"
    )
    return message

def sign_message(message: str, private_key: str) -> bytes:
    """
    Sign a message.
    
    Args:
        message: String message to sign
        private_key: Private key as hex string (with or without 0x prefix)
    
    Returns:
        bytes: The signature as bytes
    """
    return sign_bytes(message.encode('utf-8'), private_key)

def sign_bytes(message_bytes: bytes, private_key: str) -> bytes:
    """
    Sign a message bytes.
    
    Args:
        message_bytes: Message as bytes
        private_key: Private key as hex string (with or without 0x prefix)
    
    Returns:
        bytes: The signature as bytes
    """
    account = Web3().eth.account.from_key(private_key)
    
    signable_message = encode_defunct(primitive=message_bytes)
    
    signature = account.sign_message(signable_message)
    
    # Convert to bytes format [R || S || V]
    # Convert integers to 32-byte big-endian format
    r_bytes = signature.r.to_bytes(32, 'big')
    s_bytes = signature.s.to_bytes(32, 'big')
    v_bytes = bytes([signature.v])
    
    return r_bytes + s_bytes + v_bytes


def signature_to_string(signature_bytes: bytes) -> str:
    return "0x" + signature_bytes.hex()


def get_auth_token(message: str, signature: str, base_url: str, auth_token: str = None, user_agent: str = "python-gnosispay") -> str:
    """
    Obtains an authentication token by submitting a signed SIWE message.
    
    Args:
        message: The SIWE message
        signature: The signature as hex string
        base_url: Base URL for API requests
        auth_token: Authentication token (optional)
        user_agent: User agent string
    
    Returns:
        str: The authentication token
    """
    auth_request = {
        "message": message,
        "signature": signature
    }
    
    req = new_request(
        base_url=base_url,
        method="POST",
        url_str="/api/v1/auth/challenge",
        body=auth_request,
        auth_token=auth_token,
        user_agent=user_agent
    )
    
    with requests.Session() as session:
        resp = session.send(req.prepare())
        resp.raise_for_status()  # Raise exception for bad status codes
        
        auth_response = resp.json()
        token = auth_response.get("token")
        
        if not token:
            raise ValueError("No token found in response")
        
        return token

# ======== API FUNCTIONS =========

def get_request(base_url: str, auth_token: str, url_str: str, op_args: dict, parse_data: callable = None, user_agent: str = "python-gnosispay") -> any:
    """
    Get a request object.

    Args:
        base_url: Base URL for API requests
        auth_token: Authentication token
        parse_data: Function to parse the data
        user_agent: User agent string
    
    Returns:
        Data object parsed from the response
    """
    req = new_request(
        base_url=base_url,
        method="GET",
        url_str=url_str,
        body=None,
        auth_token=auth_token,
        user_agent=user_agent
    )
    with requests.Session() as session:
        resp = session.send(req.prepare())
        resp.raise_for_status()  # Raise exception for bad status codes
        data = resp.json()
        print(data)
        obj = parse_data(data, op_args)
        return obj

get_user = lambda data, _: UserAPIResponse(
    email=data.get("email", ""),
    kyc_status=data.get("kycStatus"),
    safe_wallets=data.get("safeWallets", [])
)

get_referrals = lambda data, _: UserReferralsAPIResponse(
    is_og_token_holder=data.get("isOgTokenHolder", False),
    pending_referrals=data.get("pendingReferrals", 0),
    completed_refferals=data.get("completedReferrals", 0)
)

get_rewards = lambda data, _: UserRewardsAPIResponse(
    is_og=data.get("isOg", False),
    gno_balance=data.get("gnoBalance"),
    cashback_rate=data.get("cashbackRate", 0.0)
)

get_iban_details = lambda data, _: IBANDetailsAPIResponse(
    iban=data["data"].get("iban"),
    bic=data["data"].get("bic"),
    status=data["data"].get("ibanStatus")
)

get_user_profile = lambda data, _: UserProfileAPIResponse(
        id=data.get("id"),
        email=data.get("email"),
        phone=data.get("phone"),
        first_name=data.get("firstName"),
        last_name=data.get("lastName"),
        address=data["address1"] + ("," + data["address2"] if data["address2"] else "") + "," + data["city"] + "," + data["postalCode"] + ("," + data["state"] if data["state"] else "") + "," + data["country"],
        nationality=data.get("nationalityCountry"),
        sign_in_wallets=[item["address"] for item in data.get("signInWallets", [])],
        safe_wallets=[item["address"] for item in data.get("safeWallets", [])],
        kyc_status=data.get("kycStatus")
    )

def get_transactions_for_month(
    data: dict,
    op_args: dict,
) -> List[TransactionAPIResponse]:
    mcc_codes = op_args.get("mcc_codes")
    skip_reversals = op_args.get("skip_reversals", False)

    # Create Transaction objects from response data (in reverse order)
    transactions = []
    for tx_data in reversed(data):
        transaction = TransactionAPIResponse.from_json(mcc_codes, tx_data)
        if skip_reversals and transaction.kind == "Reversal":
            continue
        if skip_reversals and transaction.status == "Reversal":
            continue
        transactions.append(transaction)
        transaction.print_transaction()
    
    return transactions

def transactions_to_csv(transactions: List[TransactionAPIResponse], filename: str) -> None:
    """
    Save a list of transactions to a CSV file.
    
    Args:
        transactions: List of Transaction objects
        filename: Output CSV filename
    """
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(TransactionAPIResponse.to_csv_header())
        for transaction in transactions:
            writer.writerow(transaction.to_csv_row())

# ======== MAIN FUNCTION =========

def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(description='Gnosis Pay API CLI')
    parser.add_argument('--privkey', required=True, help='Private key (with or without 0x prefix)')
    parser.add_argument('--option', choices=['user', 'referrals', 'rewards', 'iban', 'userprofile', 'transactions'], 
                       default='user', help='Action to perform (default: user)')
    parser.add_argument('--year', type=int, help='Year for transactions (required for transactions option)')
    parser.add_argument('--month', type=int, help='Month for transactions (required for transactions option)')
    parser.add_argument('--save', action='store_true', help='Save transactions to CSV (only works with transactions option)')
    parser.add_argument('--skip-reversals', action='store_true', help='Skip reversals in transactions')
    
    args = parser.parse_args()
    
    # Validate arguments
    if args.option == 'transactions':
        if args.year is None or args.month is None:
            parser.error("--year and --month are required for transactions option")
        if not (1 <= args.month <= 12):
            parser.error("Month must be between 1 and 12")
        if not (2000 <= args.year <= 2100):
            parser.error("Year must be between 2000 and 2100")
    
    if args.save and args.option != 'transactions':
        parser.error("--save can only be used with transactions option")
    if args.skip_reversals and args.option != 'transactions':
        parser.error("--skip-reversals can only be used with transactions option")
    
    # Authenticate
    print("=== Gnosis Pay Authentication ===")
    w3 = Web3()
    acct = w3.eth.account.from_key(args.privkey)
    address = acct.address
    print(f"Address: {address}")
    
    # Get SIWE message and authenticate
    message = get_siwe_message(DOMAIN, address, URI, CHAIN_ID, API_BASE)
    signature = signature_to_string(sign_message(message, args.privkey))
    token = get_auth_token(message, signature, API_BASE)
    print(f"✅ Authentication successful!")
    
    # Load MCC codes
    mcc_codes = read_mcc_json()
    
    # Execute requested action
    if args.option == 'user':
        print("\n=== User Information ===")
        user = get_request(API_BASE, token, "/api/v1/user", {}, get_user)
        print(f"Email: {user.email}")
        print(f"KYC Status: {user.kyc_status}")
        print(f"Safe Wallets: {user.safe_wallets}")
        
    elif args.option == 'referrals':
        print("\n=== Referral Information ===")
        referrals = get_request(API_BASE, token, "/api/v1/user/referrals", {}, get_referrals)
        print(f"Is OG Token Holder: {referrals.is_og_token_holder}")
        print(f"Pending Referrals: {referrals.pending_referrals}")
        print(f"Completed Referrals: {referrals.completed_refferals}")
        
    elif args.option == 'rewards':
        print("\n=== Rewards Information ===")
        rewards = get_request(API_BASE, token, "/api/v1/rewards", {}, get_rewards)
        print(f"OG Status: {rewards.is_og}")
        print(f"GNO Balance: {rewards.gno_balance}")
        print(f"Cashback Rate: {rewards.cashback_rate}%")
        
    elif args.option == 'iban':
        print("\n=== IBAN Information ===")
        iban_details = get_request(API_BASE, token, "/api/v1/ibans/details", {}, get_iban_details)
        if iban_details:
            print(f"IBAN: {iban_details.iban}")
            print(f"BIC: {iban_details.bic}")
            print(f"Status: {iban_details.status}")
        else:
            print("IBAN not available")
            
    elif args.option == 'userprofile':
        print("\n=== User Profile ===")
        profile = get_request(API_BASE, token, "/api/v1/user", {}, get_user_profile)
        print(f"ID: {profile.id}")
        print(f"Email: {profile.email}")
        print(f"Phone: {profile.phone}")
        print(f"First Name: {profile.first_name}")
        print(f"Last Name: {profile.last_name}")
        print(f"Address: {profile.address}")
        print(f"Nationality: {profile.nationality}")
        print(f"Sign In Wallets: {profile.sign_in_wallets}")
        print(f"Safe Wallets: {profile.safe_wallets}")
        print(f"KYC Status: {profile.kyc_status}")

    elif args.option == 'transactions':
        print(f"\n=== Transactions for {args.month}/{args.year} ===")

        # Validate month and year
        if not (1 <= args.month <= 12):
            raise ValueError("Month must be between 1 and 12")
        if args.year < 2000 or args.year > 2100:
            raise ValueError("Year must be between 2000 and 2100")
        
        # Calculate start and end dates for the month
        start_date = date(args.year, args.month, 1)
        last_day = calendar.monthrange(args.year, args.month)[1]
        end_date = date(args.year, args.month, last_day)
        
        # Format dates as ISO strings
        start_date_str = start_date.isoformat()
        end_date_str = end_date.isoformat()
        
        # Create request URL with query parameters
        url_str = f"/api/v1/transactions?after={start_date_str}&before={end_date_str}"
        params = {
            "mcc_codes": mcc_codes,
            "skip_reversals": args.skip_reversals,
        }
        transactions = get_request(API_BASE, token, url_str, params, get_transactions_for_month)
        
        if args.save:
            # Create output directory if it doesn't exist
            output_dir = "output"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
                print(f"Created output directory: {output_dir}")
            
            # Save to CSV
            filename = f"{output_dir}/{args.year}_{args.month:02d}.csv"
            transactions_to_csv(transactions, filename)
            print(f"Saved {len(transactions)} transactions to {filename}")
        else:
            # Just print transactions
            print(f"Found {len(transactions)} transactions")

if __name__ == "__main__":
    main()