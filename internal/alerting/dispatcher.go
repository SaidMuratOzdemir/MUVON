package alerting

import (
	"context"
	"log/slog"
	"time"

	"muvon/internal/alertrules"
	"muvon/internal/db"
)

const (
	// deliveryBatch bounds how many deliveries one pass leases.
	deliveryBatch = 20
	// deliveryLease is how long a leased delivery is withheld from other
	// dispatchers; it has to outlast one send.
	deliveryLease = 2 * time.Minute
	// deliverySendTimeout bounds one send.
	deliverySendTimeout = 30 * time.Second
	// maxDeliveryAttempts is how often a failing delivery is tried before it
	// is marked failed. With the backoff below that spans several hours.
	maxDeliveryAttempts = 8
)

// Dispatcher sends queued notifications. It is the only place that talks to
// Slack or SMTP, so an unreachable endpoint slows down notifications and
// nothing else.
type Dispatcher struct {
	database *db.DB
	store    *Store
	senders  map[string]Sender
	panelURL string
	wake     chan struct{}
}

// NewDispatcher builds a dispatcher for Slack and email channels. panelURL is
// the admin panel base address used in links; empty omits them.
func NewDispatcher(database *db.DB, store *Store, smtp func() SMTPConfig, panelURL string) *Dispatcher {
	return &Dispatcher{
		database: database,
		store:    store,
		senders: map[string]Sender{
			alertrules.ChannelSlack: NewSlackSender(),
			alertrules.ChannelEmail: &EmailSender{Config: smtp},
		},
		panelURL: panelURL,
		wake:     make(chan struct{}, 1),
	}
}

// Wake asks for a pass now instead of at the next tick.
func (d *Dispatcher) Wake() {
	select {
	case d.wake <- struct{}{}:
	default:
	}
}

// Run sends due deliveries until ctx ends.
func (d *Dispatcher) Run(ctx context.Context, every time.Duration) {
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		d.drain(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-d.wake:
		}
	}
}

func (d *Dispatcher) drain(ctx context.Context) {
	for ctx.Err() == nil {
		due, err := d.database.ClaimDueDeliveries(ctx, deliveryBatch, deliveryLease)
		if err != nil {
			if ctx.Err() == nil {
				slog.Warn("alerting: claim deliveries failed", "error", err)
			}
			return
		}
		for _, del := range due {
			d.deliver(ctx, del)
		}
		if len(due) < deliveryBatch {
			return
		}
	}
}

func (d *Dispatcher) deliver(ctx context.Context, del db.AlertDelivery) {
	status, reason := d.attempt(ctx, del)
	retryAt := time.Time{}
	if status == db.DeliveryPending {
		if del.Attempts >= maxDeliveryAttempts {
			status = db.DeliveryFailed
		} else {
			retryAt = time.Now().Add(deliveryBackoff(del.Attempts))
		}
	}
	if status != db.DeliverySent {
		slog.Warn("alerting: delivery not sent",
			"delivery", del.ID, "channel", del.ChannelName, "kind", del.Kind,
			"status", status, "attempt", del.Attempts, "reason", reason)
	}
	if err := d.database.CompleteDelivery(ctx, del.ID, status, reason, retryAt); err != nil {
		// The lease runs out and the delivery is retried, possibly sent twice;
		// that beats losing it.
		slog.Error("alerting: record delivery outcome failed", "delivery", del.ID, "error", err)
	}
}

// attempt sends one delivery and says what became of it: sent, pending for a
// retry, or skipped because there is nothing left to send.
func (d *Dispatcher) attempt(ctx context.Context, del db.AlertDelivery) (status, reason string) {
	ch, ok := d.store.Get().Channels[del.ChannelID]
	if !ok {
		return db.DeliverySkipped, "channel no longer exists"
	}
	if !ch.Enabled {
		return db.DeliverySkipped, "channel is disabled"
	}
	sender, ok := d.senders[ch.Kind]
	if !ok {
		return db.DeliverySkipped, "no sender for channel kind " + ch.Kind
	}

	alerts, err := d.database.GetAlertsByIDs(ctx, del.AlertIDs)
	if err != nil {
		return db.DeliveryPending, err.Error()
	}
	if len(alerts) == 0 {
		return db.DeliverySkipped, "alert no longer exists"
	}
	if del.Kind == db.DeliveryReminder && alerts[0].Acknowledged {
		return db.DeliverySkipped, "alert was acknowledged"
	}

	msg := Message{Kind: del.Kind, Alerts: alerts, Channel: ch, PanelURL: d.panelURL}
	if del.Kind == db.DeliveryDigest {
		msg.Period = del.CreatedAt.In(msg.location()).Format("02.01.2006")
	}
	sendCtx, cancel := context.WithTimeout(ctx, deliverySendTimeout)
	defer cancel()
	if err := sender.Send(sendCtx, ch, msg); err != nil {
		return db.DeliveryPending, err.Error()
	}
	if err := d.database.MarkAlertsNotified(ctx, del.AlertIDs); err != nil {
		slog.Warn("alerting: mark alerts notified failed", "delivery", del.ID, "error", err)
	}
	return db.DeliverySent, ""
}

// deliveryBackoff doubles from 30 seconds up to an hour.
func deliveryBackoff(attempt int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempt && d < time.Hour; i++ {
		d *= 2
	}
	if d > time.Hour {
		d = time.Hour
	}
	return d
}
