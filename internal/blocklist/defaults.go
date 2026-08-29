package blocklist

// DefaultPatterns is the set MUVON ships with. It is seeded into
// blocklist_patterns on startup and from then on the table is the truth: the
// operator can disable a row, change its score or add their own, and none of
// that is lost on upgrade.
//
// Rows are re-synced every boot so a new release can add patterns, but the sync
// only ever inserts missing ones and never overwrites the operator's enabled
// flag or score. A builtin row can be disabled, not deleted, because deleting
// it would just bring it back on the next boot.
//
// Every entry below was either observed in production traffic or is a direct
// sibling of something that was. Two rules were applied when choosing them:
//
//  1. Never score a file extension. ".php" on its own says nothing: an
//     appliance install may well sit in front of a real PHP application. Only
//     names that no application serves earn points.
//  2. Never score a word that appears in legitimate APIs. "config" is out;
//     "config.php" is in.
func DefaultPatterns() []Pattern {
	p := func(kind, pattern string, score int, rule, note string) Pattern {
		return Pattern{
			Kind: kind, Pattern: pattern, Score: score,
			Rule: rule, Enabled: true, Builtin: true, Note: note,
		}
	}

	return []Pattern{
		// --- Allowlist. Checked before anything else. ---
		p(KindAllow, "/.well-known/acme-challenge/", 0, "",
			"MUVON renews its own certificates here. Scoring it would let the product block its own certificate authority."),

		// --- Credential and key material. One hit is enough. ---
		p(KindFilename, ".env", ScoreSecret, RuleSecret, "Observed: repeated sweeps from cloud ranges"),
		p(KindFilename, ".env.bak", ScoreSecret, RuleSecret, ""),
		p(KindFilename, ".env.backup", ScoreSecret, RuleSecret, ""),
		p(KindFilename, ".env.backup1", ScoreSecret, RuleSecret, "Observed"),
		p(KindFilename, ".env.backup2", ScoreSecret, RuleSecret, "Observed"),
		p(KindFilename, ".env.dev", ScoreSecret, RuleSecret, ""),
		p(KindFilename, ".env.development", ScoreSecret, RuleSecret, ""),
		p(KindFilename, ".env.example", ScoreSecret, RuleSecret, ""),
		p(KindFilename, ".env.local", ScoreSecret, RuleSecret, "Observed"),
		p(KindFilename, ".env.old", ScoreSecret, RuleSecret, "Observed"),
		p(KindFilename, ".env.php", ScoreSecret, RuleSecret, "Observed"),
		p(KindFilename, ".env.php.bak", ScoreSecret, RuleSecret, "Observed"),
		p(KindFilename, ".env.prod", ScoreSecret, RuleSecret, "Observed"),
		p(KindFilename, ".env.production", ScoreSecret, RuleSecret, "Observed"),
		p(KindFilename, ".env.save", ScoreSecret, RuleSecret, "Observed"),
		p(KindFilename, ".env.stage", ScoreSecret, RuleSecret, ""),
		p(KindFilename, ".env.staging", ScoreSecret, RuleSecret, ""),
		p(KindFilename, ".env.test", ScoreSecret, RuleSecret, ""),
		p(KindFilename, "_environment", ScoreSecret, RuleSecret, "Observed"),
		p(KindFilename, "id_rsa", ScoreSecret, RuleSecret, ""),
		p(KindFilename, "id_dsa", ScoreSecret, RuleSecret, ""),
		p(KindFilename, "id_ecdsa", ScoreSecret, RuleSecret, ""),
		p(KindFilename, "id_ed25519", ScoreSecret, RuleSecret, ""),
		p(KindFilename, "secrets.json", ScoreSecret, RuleSecret, ""),
		p(KindFilename, "secrets.yml", ScoreSecret, RuleSecret, ""),

		p(KindSegment, ".aws/credentials", ScoreSecret, RuleSecret, ""),
		p(KindSegment, ".config/gcloud", ScoreSecret, RuleSecret, "Observed: application_default_credentials.json"),
		p(KindSegment, ".docker/config.json", ScoreSecret, RuleSecret, ""),
		p(KindSegment, ".git/config", ScoreSecret, RuleSecret, "Observed: probed under thirteen directory prefixes"),
		p(KindSegment, ".git/head", ScoreSecret, RuleSecret, ""),
		p(KindSegment, ".git/.env", ScoreSecret, RuleSecret, "Observed"),
		p(KindSegment, ".ssh/", ScoreSecret, RuleSecret, ""),
		p(KindSegment, ".svn/entries", ScoreSecret, RuleSecret, ""),

		// --- Exploit probes and webshell drops. Named files only. ---
		p(KindFilename, "xmlrpc.php", ScoreExploit, RuleExploit, ""),
		p(KindFilename, "xmrlpc.php", ScoreExploit, RuleExploit, "Observed: misspelled xmlrpc, a scanner signature in itself"),
		p(KindFilename, "phpinfo.php", ScoreExploit, RuleExploit, "Observed"),
		p(KindFilename, "config.php", ScoreExploit, RuleExploit, "Observed"),
		p(KindFilename, "config.php.bak", ScoreExploit, RuleExploit, "Observed"),
		p(KindFilename, "test.php", ScoreExploit, RuleExploit, "Observed"),
		p(KindFilename, "about.php", ScoreExploit, RuleExploit, "Observed"),
		p(KindFilename, "0x.php", ScoreExploit, RuleExploit, "Observed"),
		p(KindFilename, "newfile.php", ScoreExploit, RuleExploit, "Observed"),
		p(KindFilename, "shell.php", ScoreExploit, RuleExploit, ""),
		p(KindFilename, "cmd.php", ScoreExploit, RuleExploit, ""),
		p(KindFilename, "comand.php", ScoreExploit, RuleExploit, "Observed"),
		p(KindFilename, "alfa.php", ScoreExploit, RuleExploit, ""),
		p(KindFilename, "wso.php", ScoreExploit, RuleExploit, ""),
		p(KindFilename, "up.php", ScoreExploit, RuleExploit, ""),
		p(KindFilename, "upload.php", ScoreExploit, RuleExploit, ""),

		p(KindSegment, "wp-json/batch/v1", ScoreExploit, RuleExploit, "Observed: 244 requests in under six minutes"),
		p(KindSegment, "wp-json/wp/v2/users", ScoreExploit, RuleExploit, "User enumeration"),
		p(KindSegment, "wp/v2/users", ScoreExploit, RuleExploit, "Observed"),
		p(KindSegment, "wp/v2/posts", ScoreExploit, RuleExploit, "Observed"),
		p(KindSegment, "wp-content/plugins", ScoreExploit, RuleExploit, ""),
		p(KindSegment, "wp-includes/", ScoreExploit, RuleExploit, ""),

		// Webshells dropped under throwaway names. A numeric or vowel-less
		// lowercase filename ending in .php is not something an application
		// serves; the exclusions below keep ordinary front controllers out.
		p(KindRegex, `^[0-9]{1,4}\.php$`, ScoreExploit, RuleExploit,
			"Numbered shell drops: /1.php, /404.php. Observed."),
		p(KindRegex, `^(?:[bcdfghjklmnpqrstvwxyz]{5,12})\.php$`, ScoreExploit, RuleExploit,
			"Vowel-less random names: /gtghklk.php. Observed."),

		// --- Admin surface discovery. Needs company to matter. ---
		p(KindFilename, "wp-login.php", ScoreAdmin, RuleAdmin, "Observed"),
		p(KindFilename, "wp-config.php", ScoreAdmin, RuleAdmin, ""),
		p(KindFilename, "adminer.php", ScoreAdmin, RuleAdmin, ""),
		p(KindSegment, "wp-admin", ScoreAdmin, RuleAdmin, ""),
		p(KindSegment, "phpmyadmin", ScoreAdmin, RuleAdmin, ""),
		p(KindSegment, "/pma/", ScoreAdmin, RuleAdmin, ""),
		p(KindSegment, "/administrator/", ScoreAdmin, RuleAdmin, ""),

		// --- Artefacts that leak structure rather than credentials. ---
		p(KindFilename, ".ds_store", ScoreLeak, RuleLeak, ""),
		p(KindFilename, ".htpasswd", ScoreLeak, RuleLeak, ""),
		p(KindFilename, ".htaccess", ScoreLeak, RuleLeak, ""),
		p(KindFilename, "docker-compose.yml", ScoreLeak, RuleLeak, ""),
		p(KindFilename, "dockerfile", ScoreLeak, RuleLeak, ""),
	}
}
