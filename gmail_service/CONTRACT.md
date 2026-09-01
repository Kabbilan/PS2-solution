\# M2 Gmail Service Contract



\## Purpose



M2 is responsible for retrieving Gmail messages and converting

them into a normalized email structure for the rest of PhishGuard.



\---



\## Pipeline



Gmail OAuth

&#x20;   ↓

Gmail API

&#x20;   ↓

Raw Gmail Message

&#x20;   ↓

Email Parser

&#x20;   ↓

URL Extraction

&#x20;   ↓

Attachment Extraction

&#x20;   ↓

Normalized Email

&#x20;   ↓

M1 / M3 / M4



\---



\## Normalized Email Format



```json

{

&#x20; "id": "email\_001",

&#x20; "thread\_id": "thread\_001",



&#x20; "sender": "CEO <ceo@company.com>",

&#x20; "sender\_name": "CEO",

&#x20; "sender\_email": "ceo@company.com",



&#x20; "recipient": "employee@company.com",



&#x20; "subject": "Important Update",



&#x20; "body": "Please review this message.",



&#x20; "urls": \[

&#x20;   "https://example.com"

&#x20; ],



&#x20; "attachments": \[],



&#x20; "headers": {

&#x20;   "From": "CEO <ceo@company.com>",

&#x20;   "To": "employee@company.com",

&#x20;   "Subject": "Important Update"

&#x20; },



&#x20; "reply\_to": "",



&#x20; "date": "Tue, 01 Sep 2026 01:55:26 -0700"

}

