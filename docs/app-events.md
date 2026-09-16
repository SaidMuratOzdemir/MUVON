# Application events and alert rules

MUVON raises alerts from events applications write to their logs. An
application reports a failure in its own terms, such as a payment that could
not be captured or a job that is stuck, by writing a structured log line. An
event rule in the panel decides when that line becomes an alert and who hears
about it.

Nothing new is needed on either side for a new event. MUVON needs no code, and
the application needs no client library, credential or network path to MUVON:
the line travels the container log pipeline every managed container already
uses.

## The log contract

An event is one JSON object on one line of stdout or stderr, with the event's
name in a top-level `event.name` field:

```json
{"event.name": "PAYMENT_RETRY_EXHAUSTED", "level": "critical", "order_id": "A-1042", "attempts": 5}
```

- **`event.name` is required.** A JSON line without it is not an event, and a
  plain text line never is. Names are 1 to 128 characters from
  `A-Z a-z 0-9 _ . : -`. Rules match names exactly, so treat them as a stable
  interface and do not reword them.
- **Other top-level fields** are what rules filter, group and report on. Values
  compare as strings: `5` and `"5"` are the same value. A nested object is kept
  as its JSON text, so put anything a rule needs at the top level. Each value
  is cut at 1024 bytes.
- **Keep an event line under 16 KiB.** A longer line is split in transit and
  its fragments are not parsed.
- **Keep personal data out of fields a rule reports.** A notification carries
  only the fields its rule names. The full line stays on the server and is
  visible in the panel.

The key is `event.name` rather than `event` for two reasons. Several logging
libraries already use `event` for the human message, and `event.name` is the
OpenTelemetry attribute for the same thing.

### Emitting events

Python, standard library:

```python
import json
import logging
import sys


class JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "time": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        entry.update(getattr(record, "fields", {}))
        return json.dumps(entry, default=str)


handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(JSONFormatter())
logging.basicConfig(level=logging.INFO, handlers=[handler])

log = logging.getLogger("payments")
log.critical(
    "payment retries exhausted",
    extra={"fields": {"event.name": "PAYMENT_RETRY_EXHAUSTED", "order_id": order.id, "attempts": 5}},
)
```

Go, `log/slog`:

```go
logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
logger.Error("payment retries exhausted",
	"event.name", "PAYMENT_RETRY_EXHAUSTED", "order_id", order.ID, "attempts", 5)
```

Node, pino:

```js
logger.error(
  { 'event.name': 'PAYMENT_RETRY_EXHAUSTED', order_id: order.id, attempts: 5 },
  'payment retries exhausted',
)
```

Lines that are not events can stay in any format. Only event lines need to be
JSON, although making every line JSON is harmless and lets the panel filter all
of them by field.

## Rules

An event rule belongs to a project and optionally to one of its components. It
only sees lines whose project MUVON has verified: a shipper can claim a project
only for a component that runs on its own host.

### Matching

A rule has one or more clauses, and a line matches when any clause does. A
clause lists event names and optionally conditions on fields, all of which must
hold:

| Operator | Holds when |
|---|---|
| `eq` | the field is present and equals the value |
| `ne` | the field is absent or differs from the value |
| `in` | the field is present and is one of the values |
| `not_in` | the field is absent or is none of the values |
| `exists` | the field is present |

Clauses let one rule cover events that need different conditions. For
example, `PAYMENT_BLOCKED` on its own, or `JOB_FAILED` only when
`job_family` is `payment`.

### Grouping

`group_by` names a field that separates incidents. With `group_by: job_id`,
each job gets its own alert and thresholds are counted per job. Without it, the
rule has a single incident.

### Tiers

A rule has one to four tiers, listed from lowest to highest severity
(`info`, `warning`, `high`, `critical`). Each tier has a trigger, and the
highest tier whose trigger holds sets the alert's severity.

| Trigger | Holds when | Parameters |
|---|---|---|
| `each` | an event arrives | none |
| `count` | `count` events arrive within `window_seconds` | count 2 to 100000, window 1 minute to 7 days |
| `distinct` | `count` different values of `field` arrive within `window_seconds` | as `count`, plus the field |
| `baseline` | the last 24 hours hold at least `count` events and more than `ratio` times the daily average of the `baseline_days` before them | count 1 to 100000, ratio above 1 and at most 100, 1 to 7 days |

A single stuck job can warn while the same job stuck twice in two hours turns
critical: a `warning` tier on `each` and a `critical` tier on `count` with
`group_by: job_id`. A baseline tier does not fire until the rule is older than
its baseline plus a day, because until then there is no past to compare with.

### Delivery

| Mode | Notifies |
|---|---|
| `instant` | when an alert opens and when its severity rises |
| `digest` | in each channel's daily summary, at the channel's hour and time zone |
| `none` | never; the alert is recorded on the Alerts page only |

With `instant` delivery, an unacknowledged critical alert is reminded every
`remind_minutes` (15 minutes to 7 days, 0 turns reminders off; a new event
rule starts at 240).

A rule notifies its own channels, or its project's default channels when it
names none. `notify_fields` lists the fields a notification may include.

## Incidents

An alert is an incident, identified by its rule and group value:

- It opens the first time its rule fires.
- While it is open, further firings add to its occurrence count without sending
  anything new. Its severity can rise but never falls.
- Acknowledging it closes it. The next firing opens a new alert, and a
  threshold has to be crossed again: windows start no earlier than the last
  acknowledgement.
- An alert opened by a threshold counts every event that crossed it. It keeps
  the first five and the latest fifteen lines as evidence, each linked to the
  stored log line with a copy kept on the alert.
- Acknowledged alerts are purged after `retention_days`. Open alerts are never
  purged, whatever their age.

## From log line to notification

1. The shipper sends a batch and waits. diaLOG acknowledges it only after the
   lines are committed. A batch that cannot be admitted or written returns to
   the shipper, which spools it and sends it again; the Docker reader pauses
   instead of dropping lines while it waits.
2. The transaction that stores the lines also records every rule match. A batch
   sent twice after a lost acknowledgement is recognised and not counted again.
3. An evaluator turns new matches into alerts and queues their notifications in
   one transaction.
4. A dispatcher sends queued notifications and retries failures with backoff,
   eight attempts from 30 seconds up to an hour apart. The alert's detail
   shows, for each channel, whether it was sent, is still pending, failed or
   was skipped.

On a healthy installation a notification typically leaves within a few seconds
of the line being written.

## Setting up

1. On **Alarm Kuralları, Kanallar**, create a Slack or email channel and send a
   test. Email channels send through the SMTP account on the Settings page.
2. On **Proje varsayılanları**, choose each project's default channels.
3. On **Kurallar**, create a rule. **Olayları getir** lists the event names and
   fields the project logged over the last week, so the rule starts from what
   the application emits.
4. Use **Kaydet ve bir kez tetikle**. It opens a test alert and sends a test
   notification to the rule's channels; the alert's detail shows each outcome.

The builtin rules (the web rules such as path scan and brute force, plus the
certificate expiry watch) are listed on the same page. The web rules'
thresholds are on the Settings page. A builtin rule starts with delivery
`none` and uses no project defaults, so it records alerts without notifying
until it is given a delivery mode and a channel.

## API

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/alert-rules` | Builtin and event rules |
| `POST` | `/api/alert-rules` | Create an event rule |
| `GET/PUT/DELETE` | `/api/alert-rules/{id}` | A builtin rule accepts only `enabled`, `delivery`, `remind_minutes` and `channel_ids`, and cannot be deleted |
| `POST` | `/api/alert-rules/{id}/test` | Open a test alert and notify the rule's channels |
| `GET/POST` | `/api/alert-channels` | Channels; the webhook is write-only |
| `PUT/DELETE` | `/api/alert-channels/{id}` | An empty `slack_webhook` keeps the stored one |
| `POST` | `/api/alert-channels/{id}/test` | Send a sample notification now |
| `GET` | `/api/alert-projects` | Each project's default channels |
| `PUT` | `/api/alert-projects/{slug}` | Replace a project's default channels |
| `GET` | `/api/alert-events?project=&component=` | Event names and fields seen in the last 7 days |
| `GET` | `/api/alerts`, `/api/alerts/{id}` | Alerts; the detail includes deliveries |
| `POST` | `/api/alerts/{id}/acknowledge` | Close an alert |

Invalid rules are refused with `400` and a `field` naming the part that is
wrong. Unknown JSON fields are refused as well, so a misspelt key does not
pass unnoticed.

## Limits

| Limit | Value |
|---|---|
| Clauses per rule | 10 |
| Event names per clause | 20 |
| Field conditions per clause | 10 |
| Values per `in` / `not_in` | 50 |
| Tiers per rule | 4 |
| Notification fields per rule | 10 |
| Channels per rule | 20 |
| Recipients per email channel | 20 |
| Longest window or baseline | 7 days |
| Evidence lines per alert | 20 |
