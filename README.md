# digital-land-record-system

To run tests:
venv\Scripts\activate
python -m pytest tests/ -v

Tech stack:
database: SQL lite


Key generation:
python -c "import secrets; print(secrets.token_hex(32))"
output: a 64 char random key