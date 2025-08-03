# Gnosis Pay Statement Exporter

A Python CLI tool for exporting transaction data from Gnosis Pay. This tool allows you to authenticate with your Ethereum wallet and download transaction statements in CSV format.

## Features

- **SIWE Authentication**: Secure Sign-In with Ethereum authentication
- **Transaction Export**: Download transactions for any month/year
- **Multiple Data Types**: Access user info, referrals, rewards, IBAN details, and transactions
- **CSV Export**: Save transaction data to CSV files
- **Filtering**: Skip reversal transactions if needed

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/gnosispay-statement-exporter.git
   cd gnosispay-statement-exporter
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv env
   ```

3. **Activate the virtual environment**:
   ```bash
   source env/bin/activate
   ```

4. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

```
usage: main.py [-h] --privkey PRIVKEY [--option {user,referrals,rewards,iban,userprofile,transactions}] [--year YEAR] [--month MONTH] [--save] [--skip-reversals]

Gnosis Pay API CLI

options:
  -h, --help            show this help message and exit
  --privkey PRIVKEY     Private key (with or without 0x prefix)
  --option {user,referrals,rewards,iban,userprofile,transactions}
                        Action to perform (default: user)
  --year YEAR           Year for transactions (required for transactions option)
  --month MONTH         Month for transactions (required for transactions option)
  --save                Save transactions to CSV (only works with transactions option)
  --skip-reversals      Skip reversals in transactions
```

### Basic Authentication

The tool requires your Ethereum private key for authentication:

```bash
python main.py --privkey YOUR_PRIVATE_KEY
```

**Note**: Your private key can be provided with or without the `0x` prefix.

### Available Commands

#### 1. User Information (Default)
```bash
python main.py --privkey YOUR_PRIVATE_KEY
# or explicitly:
python main.py --privkey YOUR_PRIVATE_KEY --option user
```

**Output**:
```
=== Gnosis Pay Authentication ===
Address: 0xA94...
✅ Authentication successful!

=== User Information ===
Email: user@example.com
KYC Status: verified
Safe Wallets: ['0x1234...', '0x5678...']
```

#### 2. Referral Information
```bash
python main.py --privkey YOUR_PRIVATE_KEY --option referrals
```

#### 3. Rewards Information
```bash
python main.py --privkey YOUR_PRIVATE_KEY --option rewards
```

#### 4. IBAN Details
```bash
python main.py --privkey YOUR_PRIVATE_KEY --option iban
```

#### 5. User Profile
```bash
python main.py --privkey YOUR_PRIVATE_KEY --option userprofile
```

#### 6. Transaction Export

**Basic transaction listing**:
```bash
python main.py --privkey YOUR_PRIVATE_KEY --option transactions --year 2024 --month 8
```

**Export to CSV**:
```bash
python main.py --privkey YOUR_PRIVATE_KEY --option transactions --year 2024 --month 8 --save
```

**Skip reversals**:
```bash
python main.py --privkey YOUR_PRIVATE_KEY --option transactions --year 2024 --month 8 --skip-reversals
```

**Combined options**:
```bash
python main.py --privkey YOUR_PRIVATE_KEY --option transactions --year 2024 --month 8 --save --skip-reversals
```

## Data Files

The tool requires a `data/mcc_codes.json` file containing Merchant Category Code (MCC) mappings for transaction descriptions from https://github.com/greggles/mcc-codes/blob/main/mcc_codes.json.

## License

Check the LICENSE file

## Acknwoledgements

Part of the code was inspired from: https://github.com/guarilha/go-gnosispay.

## Contributing

Feel free to open Issues and/or PRs.