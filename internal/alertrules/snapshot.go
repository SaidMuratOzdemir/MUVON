package alertrules

// Snapshot is the rule and channel set dialog-siem evaluates against, loaded
// as one consistent read.
type Snapshot struct {
	Channels map[string]Channel // by id
	Rules    map[string]Rule    // by id
	// Builtins indexes builtin rules by key.
	Builtins map[string]Rule
	// ProjectChannels holds each project's default channel ids, by slug.
	ProjectChannels map[string][]string
}

// NewSnapshot indexes rows loaded from the database.
func NewSnapshot(channels []Channel, rules []Rule, projectChannels map[string][]string) *Snapshot {
	s := &Snapshot{
		Channels:        make(map[string]Channel, len(channels)),
		Rules:           make(map[string]Rule, len(rules)),
		Builtins:        make(map[string]Rule),
		ProjectChannels: projectChannels,
	}
	if s.ProjectChannels == nil {
		s.ProjectChannels = map[string][]string{}
	}
	for _, c := range channels {
		s.Channels[c.ID] = c
	}
	for _, r := range rules {
		s.Rules[r.ID] = r
		if r.Kind == KindBuiltin {
			s.Builtins[r.BuiltinKey] = r
		}
	}
	return s
}

// ChannelIDsFor returns where a rule notifies: its own channels, or, for an
// event rule that names none, its project's defaults. Disabled and unknown
// channels are left out.
func (s *Snapshot) ChannelIDsFor(r Rule) []string {
	ids := r.ChannelIDs
	if len(ids) == 0 && r.Kind == KindEvent {
		ids = s.ProjectChannels[r.ProjectSlug]
	}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if c, ok := s.Channels[id]; ok && c.Enabled {
			out = append(out, id)
		}
	}
	return out
}

// ChannelsFor is ChannelIDsFor resolved to channels.
func (s *Snapshot) ChannelsFor(r Rule) []Channel {
	ids := s.ChannelIDsFor(r)
	out := make([]Channel, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.Channels[id])
	}
	return out
}
