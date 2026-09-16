package alertrules

// Builtin keys. The correlation engine and the certificate watch raise alerts
// under these names.
const (
	BuiltinPathScan        = "path_scan"
	BuiltinAuthBruteForce  = "auth_brute_force"
	BuiltinErrorSpike      = "error_spike"
	BuiltinTrafficAnomaly  = "traffic_anomaly"
	BuiltinSensitiveAccess = "sensitive_access"
	BuiltinDataExportBurst = "data_export_burst"
	BuiltinTLSCertExpiring = "tls_cert_expiring"
)

// Builtin describes a detection that ships in code. Name and Description are
// operator-facing; the operator decides whether and where it notifies.
type Builtin struct {
	Key         string
	Name        string
	Description string
}

// BuiltinRules is the set synced into alert_rules on every muvon boot. A new
// entry reaches existing installs as a rule that records but does not
// notify, until the operator routes it.
func BuiltinRules() []Builtin {
	return []Builtin{
		{BuiltinPathScan, "Yol taraması",
			"Tek bir IP kısa sürede çok sayıda farklı adreste 404 aldığında üretilir. Tarayıcı davranışıdır."},
		{BuiltinAuthBruteForce, "Giriş kaba kuvvet denemesi",
			"Tek bir IP kısa sürede çok sayıda başarısız giriş denemesi yaptığında üretilir."},
		{BuiltinErrorSpike, "5xx hata sıçraması",
			"Bir hostta kısa sürede çok sayıda sunucu hatası döndüğünde üretilir."},
		{BuiltinTrafficAnomaly, "Trafik anomalisi",
			"Bir hostun anlık istek hızı taban hızını belirgin biçimde aştığında üretilir."},
		{BuiltinSensitiveAccess, "Hassas uçlara yoğun erişim",
			"Tanımlı hassas yollara aynı IP'den eşiği aşan sayıda istek geldiğinde üretilir."},
		{BuiltinDataExportBurst, "Veri dışa aktarma sıçraması",
			"Bir kullanıcı kısa sürede çok sayıda dışa aktarma veya indirme yaptığında üretilir."},
		{BuiltinTLSCertExpiring, "TLS sertifikası süresi doluyor",
			"Otomatik yenilenmesi gereken bir sertifikanın bitişine 14 günden az kaldığında üretilir."},
	}
}
