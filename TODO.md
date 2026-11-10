# Program

## new user

- print random totp code
- save totp code in DB

## login

- use totp code from DB for check

## recovery

- update usage to: cli recover <email/user>
- let it update the DB with new password hashes & new totp code
- ??? make it two steps, so it is closer to how real email recovery would work
  - cli recv-get <user> -> get token
  - cli recv-set <user> <new password> <token> -> reset

## DB

- add totp field
  - ??? how to save totp code
- add \[DB::update_login(Login&)\] function

